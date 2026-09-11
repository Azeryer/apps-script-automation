/**
 * WriteProxy.gs — доверенный канал ЗАПИСИ транзакций АРМ под владельцем книги.
 * Цифровой операционный контур v1.0 · Автоматизация справочника ТЭПов
 *
 * ЗАЧЕМ
 *   АРМ-деплой публикуется как «Execute as: User accessing» (обязательно ради
 *   защиты ARM_CONTROL: email пользователя должен быть надёжным). Но тогда запись
 *   в tx_journal идёт ОТ ПОЛЬЗОВАТЕЛЯ, у которого нет доступа к файлу книги и
 *   который упирается в ручные protected ranges. Дать ему доступ = сломать защиту.
 *
 *   Этот прокси — ОТДЕЛЬНЫЙ Apps Script проект, публикуемый «Execute as: Me
 *   (владелец книги)». Владелец имеет доступ к файлу И обходит protected ranges.
 *   АРМ пересылает сюда УЖЕ проверенный и подписанный пакет; прокси доверяет
 *   подписи, а не своему Session (на «Execute as: Me» Session ненадёжен), и
 *   выполняет только доверенную запись.
 *
 * ГРАНИЦА ДОВЕРИЯ
 *   ВСЯ авторизация и валидация (активен ли юзер, роль, field-level права, типы)
 *   выполняется на стороне АРМ (submitTransaction в Code.gs), где email надёжный.
 *   Прокси НЕ перепроверяет права — он тупой и доверенный: проверил HMAC → записал.
 *   Подделать пакет/автора без SHARED_SECRET нельзя. Anti-replay — дедуп по txId.
 *
 * ПУБЛИКАЦИЯ (ВАЖНО — иначе не работает)
 *   Отдельный проект, Deploy → New deployment → Web app:
 *     • «Execute as»: Me (владелец книги, owner@example.com)
 *     • «Who has access»: Anyone
 *   Script Properties этого проекта:
 *     • SHARED_SECRET   — общий с АРМ-проектом секрет подписи (одинаковый в обоих)
 *     • MASTER_DB_ID    — ID книги MasterDB
 *
 * ПРОТОКОЛ
 *   POST JSON:
 *     { ts, email, role, sig, packet }
 *   где sig = HMAC-SHA256( packet.txId + '|' + email + '|' + role + '|' + ts, SECRET ),
 *   ts — миллисекунды клиента (свежесть подписи, окно ±5 мин).
 *   Ответ: { status:'ok', txId, rowsWritten } | { status:'duplicate', txId }
 *          | { status:'error', code, message }
 */

var WP = {
  SIG_WINDOW_MS: 5 * 60 * 1000,           // допустимый разбег ts (анти-replay по свежести)
  TX_SHEET: 'tx_journal',
  TX_COLS: 15                              // ширина строки журнала
};

function doPost(e) {
  try {
    var body = JSON.parse((e && e.postData && e.postData.contents) || '{}');

    var secret = PropertiesService.getScriptProperties().getProperty('SHARED_SECRET');
    if (!secret) return _wpJson({ status: 'error', code: 'CONFIG', message: 'SHARED_SECRET не задан в Script Properties прокси' });

    var dbId = PropertiesService.getScriptProperties().getProperty('MASTER_DB_ID');
    if (!dbId) return _wpJson({ status: 'error', code: 'CONFIG', message: 'MASTER_DB_ID не задан в Script Properties прокси' });

    var ts    = Number(body.ts);
    var email = String(body.email || '').toLowerCase().trim();
    var role  = String(body.role || '').trim();
    var sig   = String(body.sig || '');
    var packet = body.packet;

    // 1. Базовая структура
    if (!email || !ts || !sig || !packet || !packet.txId) {
      return _wpJson({ status: 'error', code: 'BAD_REQUEST', message: 'Неполный запрос (email/ts/sig/packet)' });
    }

    // 2. Свежесть подписи (анти-replay по времени)
    if (Math.abs(Date.now() - ts) > WP.SIG_WINDOW_MS) {
      return _wpJson({ status: 'error', code: 'STALE', message: 'Просроченная подпись (ts вне окна)' });
    }

    // 3. Проверка HMAC — доверяем email/role ИЗ подписанного тела, а не Session
    var base = packet.txId + '|' + email + '|' + role + '|' + ts;
    if (!_wpVerify(base, sig, secret)) {
      return _wpJson({ status: 'error', code: 'BAD_SIGNATURE', message: 'Неверная подпись пакета' });
    }

    // 4. Запись под владельцем (openById обходит protected ranges владельца)
    var ss = SpreadsheetApp.openById(dbId);
    var lock = LockService.getScriptLock();
    lock.waitLock(15000);
    try {
      var tx = ss.getSheetByName(WP.TX_SHEET);
      if (!tx) throw new Error('Лист ' + WP.TX_SHEET + ' не найден');

      if (_wpIsDuplicate(tx, packet.txId)) {
        return _wpJson({ status: 'duplicate', txId: packet.txId, message: 'Транзакция уже была записана ранее' });
      }

      var serverTs = new Date();
      var rows = (packet.rows || []).map(function (r) {
        return [
          packet.txId, packet.projectId, email, role,
          r.wbsCode, r.parameterCode, r.value, r.unit || '',
          packet.armId, packet.armVersion || '', packet.payloadVersion || '1.0',
          packet.clientTimestamp || '', serverTs, _wpRowHash(packet.txId, r), r.comment || ''
        ];
      });
      if (!rows.length) return _wpJson({ status: 'error', code: 'EMPTY', message: 'Пустой массив rows' });

      var start = tx.getLastRow() + 1;
      tx.getRange(start, 1, rows.length, WP.TX_COLS).setValues(rows);
      SpreadsheetApp.flush();

      return _wpJson({ status: 'ok', txId: packet.txId, rowsWritten: rows.length });
    } finally {
      if (lock.hasLock()) lock.releaseLock();
    }

  } catch (err) {
    return _wpJson({ status: 'error', code: 'PROXY_ERROR', message: 'Сбой прокси записи: ' + err });
  }
}

/* ---------- helpers ---------- */

/** HMAC-SHA256(base, secret) → hex-строка. Совпадает с _hmacHex в Code.gs. */
function _wpHmacHex(base, secret) {
  var raw = Utilities.computeHmacSha256Signature(base, secret);
  return raw.map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

/** Постоянное по длине сравнение подписи (защита от timing-утечки). */
function _wpVerify(base, sig, secret) {
  var expected = _wpHmacHex(base, secret);
  if (expected.length !== sig.length) return false;
  var diff = 0;
  for (var i = 0; i < expected.length; i++) diff |= (expected.charCodeAt(i) ^ sig.charCodeAt(i));
  return diff === 0;
}

function _wpIsDuplicate(tx, txId) {
  var last = tx.getLastRow();
  if (last < 2) return false;
  var ids = tx.getRange(2, 1, last - 1, 1).getValues();
  for (var i = 0; i < ids.length; i++) if (ids[i][0] === txId) return true;
  return false;
}

function _wpRowHash(txId, r) {
  var raw = [txId, r.wbsCode, r.parameterCode, r.value, r.unit || ''].join('|');
  return Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, raw)
    .map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function _wpJson(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
