/**
 * SyncVOR.gs — «Синхронизатор ВОР».
 *
 * НАЗНАЧЕНИЕ
 *   Standalone Apps Script (аккаунт пользователя) с двумя функциями:
 *     1) Веб-форма «Поставить на отслеживание» (doGet) — пользователь вставляет ссылку
 *        на свой «График поставки», задаёт название проекта / лист / столбец.
 *     2) Часовой планировщик (checkAll) — обходит все отслеживаемые книги, находит
 *        НОВУЮ номенклатуру в заданном столбце и шлёт письмо-дайджест по проекту.
 *
 *   Ничего не пишет в чужие книги. Весь стейт — в отдельной книге-хранилище
 *   (STORAGE_FILE_ID), листы `tracked` и `snapshots`. Читает отслеживаемые книги через
 *   SpreadsheetApp.openById от имени владельца скрипта — нужен доступ (Viewer) к ним.
 *
 * ДЕПЛОЙ
 *   1. script.google.com → New project (standalone). Вставить SyncVOR.gs + Form.html.
 *   2. Deploy → Web app: «Выполнять от имени: Я», «Доступ: Все» (по ссылке, без входа).
 *   3. Поставить часовой триггер на checkAll: Triggers → Add Trigger →
 *      checkAll → Time-driven → Hour timer → Every hour.
 *   4. Первый прогон checkAll создаёт базовые снимки (без писем).
 */

var SYNC = {
  STORAGE_FILE_ID: 'PUT_STORAGE_FILE_ID_HERE',
  TRACKED_SHEET: 'tracked',
  SNAPSHOTS_SHEET: 'snapshots',

  // Дефолты для формы, если пользователь не задал.
  DEFAULT_SHEET_NAME: 'График поставки',
  DEFAULT_COLUMN: 'C',
  // Смещение столбца «Ед. изм.» относительно столбца наименования (для C это D = C+1).
  // Единица отслеживается ПАРНО с наименованием: ключ = наименование (C),
  // значение = единица (D). Смена единицы у существующей позиции ловится как «было→стало».
  UNIT_COLUMN_OFFSET: 1,
  // С какой строки начинаются данные номенклатуры (шапка: заголовки в стр.5, подписи в стр.6).
  DATA_START_ROW: 7,

  // ТЕСТОВЫЙ получатель (временно, пока не настроим почты в форме).
  TEST_RECIPIENT: 'owner@example.com',

  // Служебные значения столбца, которые НЕ являются номенклатурой (шапки/подписи).
  IGNORE_VALUES: ['ПТО', 'Снабжение', 'Производство']
};

/* ==================== WEB UI ==================== */

function doGet() {
  return HtmlService.createTemplateFromFile('Form')
    .evaluate()
    .setTitle('Поставить на отслеживание')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ============ ДОВЕРЕННЫЙ ПРИЁМ ИЗ КОНТУРА ТЭП (write-proxy) ============ */
/**
 * doPost — приёмный канал для постановки ВОР на мониторинг ИЗ контура ТЭП.
 *
 * ЗАЧЕМ. Форма «Поставить ВОР на мониторинг» живёт в АРМ-деплое контура ТЭП
 * («Execute as: User accessing» — ради гейта sys_users). Под пользователем нет
 * доступа к чужим книгам ВОР и к книге-хранилищу владельца, поэтому сам
 * addTracking там выполнить нельзя. Контур подписывает заявку HMAC и шлёт сюда;
 * этот проект развёрнут «Execute as: Me (владелец)» → у него есть Viewer-доступ
 * к книгам ВОР и полный доступ к хранилищу. Проверяем подпись → выполняем addTracking.
 *
 * ГРАНИЦА ДОВЕРИЯ. Авторизация (активен ли юзер в sys_users) сделана на стороне
 * контура, где email надёжный. Здесь Session ненадёжен (Execute as: Me) — доверяем
 * ТОЛЬКО HMAC-подписи. Секрет SHARED_SECRET_VOR (Script Property) — отдельный от
 * MasterDB-write-proxy. Свежесть — окно ±5 мин по ts.
 *
 * ПРОТОКОЛ. POST JSON: { ts, email, sig, form },
 *   sig = HMAC-SHA256( 'trackvor|' + email + '|' + ts, SHARED_SECRET_VOR ).
 *   form = { url, projectName, sheetName, column } — как у addTracking.
 * Ответ = ответ addTracking ({ ok, message, ... }) либо { ok:false, message }.
 */
function doPost(e) {
  try {
    var body = JSON.parse((e && e.postData && e.postData.contents) || '{}');
    var secret = PropertiesService.getScriptProperties().getProperty('SHARED_SECRET_VOR');
    if (!secret) return _vorJson({ ok: false, message: 'SHARED_SECRET_VOR не задан в Script Properties SyncVOR.' });

    var ts    = Number(body.ts);
    var email = String(body.email || '').toLowerCase().trim();
    var sig   = String(body.sig || '');
    var form  = body.form;

    // form нужен только для постановки (add); для list его нет — не требуем.
    if (!email || !ts || !sig) {
      return _vorJson({ ok: false, message: 'Неполный запрос (email/ts/sig).' });
    }
    if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return _vorJson({ ok: false, message: 'Просроченная подпись (ts вне окна ±5 мин).' });
    }
    var base = 'trackvor|' + email + '|' + ts;
    if (!_vorVerify(base, sig, secret)) {
      return _vorJson({ ok: false, message: 'Неверная подпись заявки.' });
    }

    // Маршрут по action. По умолчанию (нет action) — постановка на мониторинг
    // (обратная совместимость с прежним протоколом trackVorSubmit).
    var action = String(body.action || 'add').toLowerCase();
    if (action === 'list') {
      // Только чтение реестра отслеживаемых книг (для формы-реестра в контуре ТЭП).
      return _vorJson(listTracking());
    }

    // Постановка на мониторинг под владельцем — здесь form обязателен.
    if (!form) {
      return _vorJson({ ok: false, message: 'Неполный запрос (нет form для постановки).' });
    }
    var res = addTracking(form);
    return _vorJson(res);
  } catch (err) {
    return _vorJson({ ok: false, message: 'Сбой приёма заявки: ' + err });
  }
}

/** HMAC-SHA256(base, secret) → hex. Совпадает с _hmacHex в контуре ТЭП. */
function _vorHmacHex(base, secret) {
  var raw = Utilities.computeHmacSha256Signature(base, secret);
  return raw.map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

/** Постоянное по длине сравнение подписи (защита от timing-утечки). */
function _vorVerify(base, sig, secret) {
  var expected = _vorHmacHex(base, secret);
  if (expected.length !== sig.length) return false;
  var diff = 0;
  for (var i = 0; i < expected.length; i++) diff |= (expected.charCodeAt(i) ^ sig.charCodeAt(i));
  return diff === 0;
}

function _vorJson(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Вызывается из формы (google.script.run). Добавляет книгу в отслеживание.
 * @param {Object} form { url, projectName, sheetName, column }
 * @return {Object} { ok, message, projectName, fileId }
 */
function addTracking(form) {
  try {
    var url = String((form && form.url) || '').trim();
    if (!url) return { ok: false, message: 'Не указана ссылка на документ.' };

    var fileId = _extractFileId(url);
    if (!fileId) return { ok: false, message: 'Не удалось распознать ID документа в ссылке.' };

    var sheetName = String((form && form.sheetName) || '').trim() || SYNC.DEFAULT_SHEET_NAME;
    var column = String((form && form.column) || '').trim().toUpperCase() || SYNC.DEFAULT_COLUMN;
    var projectName = String((form && form.projectName) || '').trim();

    // Проверяем доступ и что лист существует.
    var ss;
    try {
      ss = SpreadsheetApp.openById(fileId);
    } catch (e) {
      return { ok: false, message: 'Нет доступа к документу или неверная ссылка. ' +
        'Дайте доступ (хотя бы «Просмотр») аккаунту, от которого работает скрипт.' };
    }
    var sh = ss.getSheetByName(sheetName);
    if (!sh) {
      return { ok: false, message: 'В книге нет листа «' + sheetName + '». ' +
        'Проверьте имя листа.' };
    }
    if (!projectName) projectName = ss.getName();

    var store = SpreadsheetApp.openById(SYNC.STORAGE_FILE_ID);
    var tracked = store.getSheetByName(SYNC.TRACKED_SHEET);

    // Уже отслеживается такой fileId+лист+столбец?
    var data = tracked.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][1]) === fileId &&
          String(data[i][2]) === sheetName &&
          String(data[i][3]).toUpperCase() === column) {
        return { ok: false, message: 'Этот документ (лист «' + sheetName +
          '», столбец ' + column + ') уже на отслеживании.' };
      }
    }

    tracked.appendRow([
      projectName, fileId, sheetName, column,
      SYNC.TEST_RECIPIENT,   // recipients: пока тестовый адрес
      true,                  // enabled
      new Date()             // addedAt
    ]);
    SpreadsheetApp.flush();

    // Сразу сделаем базовый снимок, чтобы уже существующая номенклатура не улетела
    // как «новая» при первом же прогоне.
    _saveSnapshot(fileId, _readItems(sh, column).units);

    return { ok: true, message: 'Документ поставлен на отслеживание.',
             projectName: projectName, fileId: fileId };
  } catch (err) {
    return { ok: false, message: 'Ошибка: ' + err };
  }
}

/**
 * Возвращает реестр отслеживаемых книг (только чтение) для формы-реестра в контуре ТЭП.
 * Читает лист `tracked` книги-хранилища, отдаёт только enabled-записи.
 * @return {Object} { ok:true, items:[{projectName, url, addedAt}] } | { ok:false, message }
 */
function listTracking() {
  try {
    var store = SpreadsheetApp.openById(SYNC.STORAGE_FILE_ID);
    var tracked = store.getSheetByName(SYNC.TRACKED_SHEET);
    var rows = tracked.getDataRange().getValues();
    var items = [];
    for (var i = 1; i < rows.length; i++) {
      var projectName = String(rows[i][0] || '');
      var fileId = String(rows[i][1] || '');
      var enabled = rows[i][5];
      var addedAt = rows[i][6];
      if (!fileId) continue;
      if (enabled !== true && String(enabled).toLowerCase() !== 'true') continue;
      items.push({
        projectName: projectName,
        url: 'https://docs.google.com/spreadsheets/d/' + fileId + '/edit',
        addedAt: (addedAt instanceof Date) ? addedAt.toISOString() : String(addedAt || '')
      });
    }
    return { ok: true, items: items };
  } catch (err) {
    return { ok: false, message: 'Не удалось прочитать реестр: ' + err };
  }
}

/* ==================== ПЛАНИРОВЩИК ==================== */

/**
 * Часовой обход. Для каждой enabled-записи: читает столбец, сравнивает со снимком,
 * при новых наименованиях шлёт письмо по проекту и обновляет снимок.
 */
function checkAll() {
  var store = SpreadsheetApp.openById(SYNC.STORAGE_FILE_ID);
  var tracked = store.getSheetByName(SYNC.TRACKED_SHEET);
  var rows = tracked.getDataRange().getValues();

  for (var i = 1; i < rows.length; i++) {
    var projectName = String(rows[i][0] || '');
    var fileId = String(rows[i][1] || '');
    var sheetName = String(rows[i][2] || '') || SYNC.DEFAULT_SHEET_NAME;
    var column = (String(rows[i][3] || '') || SYNC.DEFAULT_COLUMN).toUpperCase();
    var recipients = String(rows[i][4] || '').trim() || SYNC.TEST_RECIPIENT;
    var enabled = rows[i][5];

    if (enabled !== true && String(enabled).toLowerCase() !== 'true') continue;
    if (!fileId) continue;

    try {
      var ss = SpreadsheetApp.openById(fileId);
      var sh = ss.getSheetByName(sheetName);
      if (!sh) continue;

      var cur = _readItems(sh, column);   // { names: [...], units: {name→unit} }
      var prev = _loadSnapshot(fileId);   // {name→unit} | null

      if (prev === null) {
        // Первый раз видим — базовый снимок, письма НЕ шлём.
        _saveSnapshot(fileId, cur.units);
        continue;
      }

      // Диф по ключу-наименованию.
      var addedItems = [];   // [{name, unit}]                — новые наименования
      var changedItems = []; // [{name, unit, prevUnit}]      — сменилась ед.изм.
      var removedItems = []; // [{name, unit}]                — исчезли (unit = последняя известная)

      for (var c = 0; c < cur.names.length; c++) {
        var name = cur.names[c];
        var unit = cur.units[name];
        if (!prev.hasOwnProperty(name)) {
          addedItems.push({ name: name, unit: unit });
        } else if (String(prev[name]) !== '' && String(prev[name]) !== String(unit)) {
          // prevUnit==='' → единица в старом снимке неизвестна (миграция со старого
          // формата); не считаем сменой, просто дадим ей записаться в новый снимок.
          changedItems.push({ name: name, unit: unit, prevUnit: prev[name] });
        }
      }
      for (var pn in prev) {
        if (prev.hasOwnProperty(pn) && !cur.units.hasOwnProperty(pn)) {
          removedItems.push({ name: pn, unit: prev[pn] });
        }
      }

      if (addedItems.length || changedItems.length || removedItems.length) {
        _sendDigest(projectName, ss.getName(), fileId, sheetName, column, recipients,
                    addedItems, changedItems, removedItems);
      }
      // Обновляем снимок в любом случае (фиксируем текущее состояние).
      _saveSnapshot(fileId, cur.units);
    } catch (e) {
      // Недоступная книга / ошибка — не роняем весь обход, идём дальше.
      // (Опционально можно логировать в отдельный лист.)
    }
  }
}

/* ==================== ПИСЬМО ==================== */

/**
 * Формирует и шлёт письмо-дайджест по проекту.
 * @param {Array<{name,unit}>}          added   новая номенклатура
 * @param {Array<{name,unit,prevUnit}>} changed сменилась ед.изм.
 * @param {Array<{name,unit}>}          removed удалённые позиции
 */
function _sendDigest(projectName, bookName, fileId, sheetName, column,
                     recipients, added, changed, removed) {
  var url = 'https://docs.google.com/spreadsheets/d/' + fileId + '/edit';

  // Тема: перечисляем только непустые категории.
  var parts = [];
  if (added.length)   parts.push('новых: ' + added.length);
  if (changed.length) parts.push('смена ед.изм.: ' + changed.length);
  if (removed.length) parts.push('удалено: ' + removed.length);
  var subject = 'Синхронизатор ВОР: изменения — ' + (projectName || bookName) +
                ' (' + parts.join(', ') + ')';

  var lines = [];
  lines.push('Проект: ' + (projectName || bookName));
  lines.push('Документ: ' + bookName);
  lines.push('Лист: ' + sheetName + ', столбец наименования: ' + column);
  lines.push('Ссылка: ' + url);

  if (added.length) {
    lines.push('');
    lines.push('НОВАЯ НОМЕНКЛАТУРА (' + added.length + '):');
    for (var i = 0; i < added.length; i++) {
      lines.push('  ' + (i + 1) + '. ' + _pair(added[i].name, added[i].unit));
    }
  }

  if (changed.length) {
    lines.push('');
    lines.push('ИЗМЕНИЛАСЬ ЕД. ИЗМ. (' + changed.length + '):');
    for (var j = 0; j < changed.length; j++) {
      var ch = changed[j];
      lines.push('  ' + (j + 1) + '. ' + ch.name +
                 ' — было «' + (ch.prevUnit || '—') + '», стало «' + (ch.unit || '—') + '»');
    }
  }

  if (removed.length) {
    lines.push('');
    lines.push('УДАЛЕНА ПОЗИЦИЯ (' + removed.length + '):');
    for (var k = 0; k < removed.length; k++) {
      lines.push('  ' + (k + 1) + '. ' + _pair(removed[k].name, removed[k].unit));
    }
  }

  lines.push('');
  lines.push('— Мониторинг ВОР (автоматическое уведомление)');

  var body = lines.join('\n');
  var to = recipients.split(/[;,]/).map(function (s) { return s.trim(); })
                     .filter(function (s) { return s; }).join(',');
  MailApp.sendEmail(to, subject, body);
}

/** «наименование — единица» (единица может быть пустой). */
function _pair(name, unit) {
  return unit ? (name + ' — ' + unit) : name;
}

/* ==================== ЧТЕНИЕ СТОЛБЦА ==================== */

/**
 * Читает пары «наименование (columnLetter) + единица измерения (columnLetter+offset)»
 * построчно, начиная с DATA_START_ROW. Наименование нормализуется и служит КЛЮЧОМ;
 * единица нормализуется и служит значением. Пустые и служебные (IGNORE_VALUES)
 * наименования отбрасываются. При дубле наименования берётся ПЕРВОЕ вхождение.
 *
 * @return {{names: Array<string>, units: Object<string,string>}}
 *   names — наименования в порядке появления (для стабильного вывода);
 *   units — карта наименование→единица.
 */
function _readItems(sh, columnLetter) {
  var nameIdx = _colLetterToIndex(columnLetter);              // 1-based
  var unitIdx = nameIdx + (SYNC.UNIT_COLUMN_OFFSET || 1);     // соседний столбец справа
  var lastRow = sh.getLastRow();
  if (lastRow < SYNC.DATA_START_ROW) return { names: [], units: {} };

  var n = lastRow - SYNC.DATA_START_ROW + 1;
  var width = unitIdx - nameIdx + 1;                          // читаем блок [name..unit]
  var block = sh.getRange(SYNC.DATA_START_ROW, nameIdx, n, width).getValues();

  var names = [];
  var units = {};
  for (var r = 0; r < block.length; r++) {
    var rawName = block[r][0];
    if (rawName === null || rawName === undefined) continue;
    var name = _normalize(rawName);
    if (!name) continue;
    if (SYNC.IGNORE_VALUES.indexOf(name) !== -1) continue;
    if (units.hasOwnProperty(name)) continue;                 // дубль наименования → первое
    var rawUnit = block[r][width - 1];
    var unit = _normalize(rawUnit === null || rawUnit === undefined ? '' : rawUnit);
    names.push(name);
    units[name] = unit;
  }
  return { names: names, units: units };
}

function _normalize(v) {
  return String(v).replace(/\s+/g, ' ').trim();
}

function _colLetterToIndex(letter) {
  var s = String(letter).toUpperCase().replace(/[^A-Z]/g, '');
  if (!s) throw new Error('Неверная буква столбца: ' + letter);
  var idx = 0;
  for (var i = 0; i < s.length; i++) idx = idx * 26 + (s.charCodeAt(i) - 64);
  return idx;
}

/* ==================== СНИМКИ ==================== */

function _snapshotSheet() {
  return SpreadsheetApp.openById(SYNC.STORAGE_FILE_ID).getSheetByName(SYNC.SNAPSHOTS_SHEET);
}

/**
 * Загружает прошлый снимок как карту наименование→единица.
 * Совместимость: старый формат снимка — JSON-массив наименований (без единиц);
 * такой массив читается как {наименование: ''} (единица неизвестна), чтобы
 * первый прогон после обновления не выдал лавину «изменилась ед.изм.».
 * @return {Object<string,string>|null} карта, либо null если снимка ещё нет.
 */
function _loadSnapshot(fileId) {
  var sh = _snapshotSheet();
  var data = sh.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]) === fileId) {
      var parsed;
      try { parsed = JSON.parse(data[i][1] || '{}'); }
      catch (e) { return {}; }
      if (Array.isArray(parsed)) {              // старый формат: массив наименований
        var map = {};
        for (var k = 0; k < parsed.length; k++) map[String(parsed[k])] = '';
        return map;
      }
      return parsed || {};                       // новый формат: {наименование: единица}
    }
  }
  return null;
}

/** Сохраняет снимок как карту наименование→единица (JSON-объект). */
function _saveSnapshot(fileId, unitsMap) {
  var sh = _snapshotSheet();
  var data = sh.getDataRange().getValues();
  var json = JSON.stringify(unitsMap || {});
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]) === fileId) {
      sh.getRange(i + 1, 2).setValue(json);
      sh.getRange(i + 1, 3).setValue(new Date());
      SpreadsheetApp.flush();
      return;
    }
  }
  sh.appendRow([fileId, json, new Date()]);
  SpreadsheetApp.flush();
}

/* ==================== HELPERS ==================== */

/** Извлекает fileId из ссылки Google Sheets (/d/<id>/) или из «голого» id. */
function _extractFileId(url) {
  var m = String(url).match(/\/d\/([a-zA-Z0-9_-]{20,})/);
  if (m) return m[1];
  m = String(url).match(/[?&]id=([a-zA-Z0-9_-]{20,})/);
  if (m) return m[1];
  // Голый id.
  if (/^[a-zA-Z0-9_-]{20,}$/.test(String(url).trim())) return String(url).trim();
  return null;
}

/** Позволяет include HTML-фрагментов в шаблоне, если понадобится. */
function include(name) {
  return HtmlService.createHtmlOutputFromFile(name).getContent();
}
