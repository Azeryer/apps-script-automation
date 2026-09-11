/**
 * Gateway.gs — транзакционный шлюз на событийном журнале (event sourcing).
 *
 * Фрагмент серверной части цифрового операционного контура производственно-
 * строительной компании. Вынесен из боевого Code.gs без изменений логики; обезличен.
 *
 * ИДЕЯ
 *   Данные никогда не перезаписываются. Любое изменение — строка в append-only
 *   журнале tx_journal. Текущее состояние (view_current_state) — пересбираемая
 *   витрина: последняя запись на ключ projectId|wbsCode|parameterCode.
 *   Итог: полная история «кто / что / когда / чем перекрыто» и восстановимое состояние.
 *
 * ЗАЩИТНЫЕ МЕХАНИЗМЫ
 *   • LockService — дедуп и запись под единой блокировкой (конкурентные записи).
 *   • Идемпотентность — повторный txId не создаёт дубль (status:'duplicate').
 *   • Серверная роль — роль, присланная клиентом, игнорируется; берётся из sys_users.
 *   • Наблюдаемость — каждый запрос ложится в log_api_requests с длительностью в мс.
 */

// ========== ГЛАВНЫЙ ШЛЮЗ ==========

/**
 * Главный транзакционный шлюз: валидация → дедуп → атомарная пакетная запись.
 * @param {Object} packet — пакет транзакции.
 * @param {string} [trustedEmail] — доверенный email автора. Если задан — берётся он
 *   (используется write-proxy, где email пришёл из HMAC-подписи, а Session ненадёжен).
 *   Если НЕ задан — email берётся из Session.getActiveUser() (прямой вызов владельцем).
 */
function processTransaction(packet, trustedEmail) {
  var t0 = Date.now();
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var lock = LockService.getScriptLock();
  var email = (trustedEmail != null && trustedEmail !== '')
    ? String(trustedEmail).toLowerCase().trim()
    : (Session.getActiveUser().getEmail() || '').toLowerCase().trim();

  try {
    // 0. Структурная проверка пакета
    var sErr = validatePacketShape(packet);
    if (sErr) return fail(ss, packet, email, 'VALIDATION_ERROR', sErr, t0);

    // 1. Авторизация + серверная роль (клиентская роль игнорируется)
    var user = getActiveUser(ss, email);
    if (!user) return fail(ss, packet, email, 'UNAUTHORIZED', 'Аккаунт не активен в sys_users', t0);

    // 2. Право роли на запись в данный АРМ
    if (!canWrite(ss, user.role, packet.armId)) {
      return fail(ss, packet, email, 'FORBIDDEN',
        'Роль ' + user.role + ' не вправе писать в ' + packet.armId, t0);
    }

    // 3. Валидация строк по sys_parameters (наличие · права АРМ · тип · field-level роль)
    var rErr = validateRows(ss, packet.rows, packet.armId, user.role);
    if (rErr) return fail(ss, packet, email, 'VALIDATION_ERROR', rErr, t0);

    // 4. Дедуп + запись под единой блокировкой (дедуп идёт по tx_journal, не по логу!)
    lock.waitLock(15000);
    var tx = ss.getSheetByName('tx_journal');

    if (isDuplicate(tx, packet.txId)) {
      lock.releaseLock();
      logRequest(ss, packet, email, 'DUPLICATE', 0, 'Повторная транзакция', Date.now() - t0);
      return { status: 'duplicate', txId: packet.txId, message: 'Транзакция уже была записана ранее' };
    }

    var serverTs = new Date();
    var rows = packet.rows.map(function (r) {
      return [
        packet.txId, packet.projectId, email, user.role,
        r.wbsCode, r.parameterCode, r.value, r.unit || '',
        packet.armId, packet.armVersion || '', packet.payloadVersion || '1.0',
        packet.clientTimestamp || '', serverTs, rowHash(packet.txId, r), r.comment || ''
      ];
    });

    var start = tx.getLastRow() + 1;
    tx.getRange(start, 1, rows.length, rows[0].length).setValues(rows);
    SpreadsheetApp.flush();
    lock.releaseLock();

    logRequest(ss, packet, email, 'SUCCESS', rows.length, '', Date.now() - t0);
    return { status: 'ok', txId: packet.txId, rowsWritten: rows.length };

  } catch (err) {
    if (lock.hasLock()) lock.releaseLock();
    logError(ss, packet, email, err);
    logRequest(ss, packet, email, 'CRITICAL_ERROR', 0, String(err), Date.now() - t0);
    return { status: 'error', message: 'Критический сбой шлюза: ' + err };
  }
}

// ========== ХЕЛПЕРЫ ШЛЮЗА ==========

function fail(ss, packet, email, status, msg, t0) {
  logRequest(ss, packet, email, status, 0, msg, Date.now() - t0);
  return { status: 'error', code: status, message: msg };
}

function validatePacketShape(p) {
  if (!p) return 'Пустой пакет';
  if (!p.txId) return 'Нет txId';
  if (!p.projectId) return 'Нет projectId';
  if (!p.armId) return 'Нет armId';
  if (!Array.isArray(p.rows) || !p.rows.length) return 'Пустой массив rows';
  for (var i = 0; i < p.rows.length; i++) {
    var r = p.rows[i];
    if (!r.wbsCode) return 'Строка ' + i + ': нет wbsCode';
    if (!r.parameterCode) return 'Строка ' + i + ': нет parameterCode';
    if (r.value === null || r.value === undefined || r.value === '') return 'Строка ' + i + ': пустое value';
  }
  return null;
}

function isDuplicate(tx, txId) {
  var last = tx.getLastRow();
  if (last < 2) return false;
  var ids = tx.getRange(2, 1, last - 1, 1).getValues();
  for (var i = 0; i < ids.length; i++) if (ids[i][0] === txId) return true;
  return false;
}

function rowHash(txId, r) {
  var raw = [txId, r.wbsCode, r.parameterCode, r.value, r.unit || ''].join('|');
  return Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, raw)
    .map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function logRequest(ss, p, email, status, n, msg, ms) {
  try {
    ss.getSheetByName('log_api_requests').appendRow([
      'REQ-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      new Date(), p ? p.txId : '', p ? p.armId : '', email,
      p ? p.projectId : '', p ? p.payloadType : '', n, status, msg, ms
    ]);
  } catch (e) {}
}

function logError(ss, p, email, err) {
  try {
    ss.getSheetByName('log_errors').appendRow([
      'ERR-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      new Date(), p ? p.txId : '', p ? p.armId : '', email,
      p ? p.projectId : '', 'RUNTIME', String(err), (err && err.stack) || ''
    ]);
  } catch (e) {}
}

// ========== ВИТРИНЫ ==========

/**
 * Пересборка витрины: последняя запись по serverTimestamp на ключ
 * projectId|wbsCode|parameterCode. Витрина хранит и автора последней правки
 * (author = email из tx_journal r[2]) — ARM_CONTROL показывает «кто внёс».
 * Колонки: projectId | wbsCode | parameterCode | value | unit | serverTimestamp | author
 */
function rebuildCurrentViews() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var tx = ss.getSheetByName('tx_journal');
  var last = tx.getLastRow();
  if (last < 2) return;
  var data = tx.getRange(2, 1, last - 1, 13).getValues();
  var latest = {};
  data.forEach(function (r) {
    var key = r[1] + '|' + r[4] + '|' + r[5];
    var ts = new Date(r[12]).getTime();
    if (!latest[key] || ts >= latest[key].ts) {
      // r[2] = author (email), r[3] = role. В витрину тащим author.
      latest[key] = { ts: ts, row: [r[1], r[4], r[5], r[6], r[7], r[12], r[2]] };
    }
  });
  var out = Object.keys(latest).map(function (k) { return latest[k].row; });
  var view = ss.getSheetByName('view_current_state') || ss.insertSheet('view_current_state');
  view.clearContents();
  view.getRange(1, 1, 1, 7)
      .setValues([['projectId', 'wbsCode', 'parameterCode', 'value', 'unit', 'serverTimestamp', 'author']]);
  if (out.length) view.getRange(2, 1, out.length, 7).setValues(out);
}

// ========== КЭШ СПРАВОЧНИКОВ (производительность) ==========
// Медленно меняющиеся NSI-листы читаются из CacheService (TTL), а не из Sheets
// на каждый запрос. Один getValues() к Sheets ≈ 100–300 мс; кэш ≈ единицы мс.
// Плюс per-request мемоизация (_reqCache) — в пределах одного вызова функции
// лист не сериализуется/десериализуется повторно.
// ⚠ Инвалидация: AdminBridge при любой записи вызывает invalidateSheetCache()
// (см. AdminBridge.gs). В боевой работе Bridge не используется, изменения НСИ
// редки → TTL достаточно. Живые данные (view_current_state, sys_projects,
// tx_journal) НЕ кэшируются — читаются напрямую.
var CACHE_TTL_SEC = 300; // 5 минут
var CACHED_SHEETS = {
  'sys_users': true, 'sys_parameters': true, 'sys_stage_fields': true,
  'sys_role_fields': true, 'sys_arm_registry': true, 'sys_permissions': true
};
var _reqCache = {}; // мемоизация в пределах одного исполнения

/**
 * Возвращает ВСЕ значения листа (включая строку заголовка) как 2D-массив,
 * с кэшированием справочников. Для некэшируемых листов — прямое чтение.
 */
function _readSheetCached(ss, name) {
  if (_reqCache[name]) return _reqCache[name];
  var values;
  if (CACHED_SHEETS[name]) {
    var cache = CacheService.getScriptCache();
    var key = 'sheet:' + name;
    var hit = cache.get(key);
    if (hit) {
      values = JSON.parse(hit);
    } else {
      values = _rawRead(ss, name);
      try { cache.put(key, JSON.stringify(values), CACHE_TTL_SEC); } catch (e) { /* >100KB — пропускаем кэш */ }
    }
  } else {
    values = _rawRead(ss, name);
  }
  _reqCache[name] = values;
  return values;
}

function _rawRead(ss, name) {
  var sh = ss.getSheetByName(name);
  if (!sh || sh.getLastRow() < 1) return [];
  return sh.getDataRange().getValues();
}

/** Сброс кэша листа(ов). Вызывается из AdminBridge после записи. */
function invalidateSheetCache(names) {
  var cache = CacheService.getScriptCache();
  var list = names && names.length ? names : Object.keys(CACHED_SHEETS);
  var keys = list.map(function (n) { return 'sheet:' + n; });
  cache.removeAll(keys);
  _reqCache = {};
}

/**
 * РУЧНОЙ СБРОС КЭША. Запускать после ручной правки sys_users/ролей/НСИ прямо в
 * таблице (когда изменения нужны сразу, не дожидаясь TTL 5 мин).
 * Способы запуска:
 *   1) Редактор Apps Script → выбрать функцию refreshCache → ▶ Run.
 *   2) Меню самой таблицы «🔧 Контур» → «Сбросить кэш справочников» (см. onOpen).
 * Возвращает строку-статус (видна в логе исполнения / всплывающем окне меню).
 */
function refreshCache() {
  invalidateSheetCache();
  var msg = 'Кэш справочников сброшен: ' + Object.keys(CACHED_SHEETS).join(', ');
  Logger.log(msg);
  return msg;
}
