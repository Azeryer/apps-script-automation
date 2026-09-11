/**
 * RoleModel.gs — ролевая модель доступа на уровне ОТДЕЛЬНЫХ ПОЛЕЙ.
 *
 * Фрагмент серверной части цифрового операционного контура; обезличен.
 *
 * ИДЕЯ
 *   Права не зашиты в код, а лежат в справочниках (НСИ):
 *     sys_users        — кто активен и с какой ролью;
 *     sys_permissions  — какая роль в какой АРМ может писать;
 *     sys_role_fields  — матрица «роль × параметр» (доступ к конкретному полю);
 *     sys_parameters   — реестр параметров (тип, домен).
 *   Новая роль или перераспределение полей = строки в таблице, без правки кода
 *   и редеплоя. Матрица собрана из реальных колонок «ответственный» в справочнике.
 *
 * ДВА БАРЬЕРА (принципиально)
 *   1. Видимость: форма отдаёт роли только её поля (_roleAllowedCodes).
 *   2. Запись: validateRows заново проверяет ту же матрицу на сервере.
 *   Скрыть поле в UI — не защита: клиент можно подменить, поэтому второй барьер обязателен.
 *
 * Зависимость: _readSheetCached() — см. 02-event-sourcing-gateway/Gateway.gs
 */

function getActiveUser(ss, email) {
  var values = _readSheetCached(ss, 'sys_users');
  if (values.length < 2) return null;
  var data = values.slice(1);
  for (var i = 0; i < data.length; i++) {
    if (String(data[i][0]).toLowerCase().trim() === email && String(data[i][2]).trim() === 'Активен') {
      return { email: email, role: String(data[i][1]).trim() };
    }
  }
  return null;
}

/**
 * Роль текущего пользователя (по активному email → sys_users).
 * Возвращает строку роли или '' если пользователь не найден/не активен.
 * Используется формами этапов для field-level фильтра видимости.
 */
function getCurrentRole(ss) {
  var email = (Session.getActiveUser().getEmail() || '').toLowerCase().trim();
  if (!email) return '';
  var user = getActiveUser(ss, email);
  return user ? user.role : '';
}

/**
 * Страховочный барьер авторизации для серверных data-функций (google.script.run).
 * Бросает исключение, если вызывающий не активен в sys_users. Клиент показывает
 * ошибку. Дублирует гейт doGet на случай прямого вызова функции в обход рендера.
 * Возвращает {email, role} для дальнейшего использования.
 */
function _requireUser(ss) {
  var email = (Session.getActiveUser().getEmail() || '').toLowerCase().trim();
  var user = email ? getActiveUser(ss, email) : null;
  if (!user) throw new Error('Доступ запрещён: аккаунт не авторизован в системе');
  return user;
}

/**
 * Множество parameterCode, разрешённых роли (из sys_role_fields).
 * Возвращает объект-словарь { code: true } для быстрой проверки, ЛИБО
 * null — если роль = ROLE_ADMIN (без фильтра, видит все поля).
 * Роль без строк в sys_role_fields → пустой словарь (видит 0 полей).
 */
function _roleAllowedCodes(ss, role) {
  if (role === 'ROLE_ADMIN') return null; // wildcard: без фильтра
  var out = {};
  var values = _readSheetCached(ss, 'sys_role_fields');
  if (values.length < 2) return out;
  var data = values.slice(1);
  for (var i = 0; i < data.length; i++) {
    if (String(data[i][0]).trim() === role) out[String(data[i][1]).trim()] = true;
  }
  return out;
}

function canWrite(ss, role, armId) {
  var values = _readSheetCached(ss, 'sys_permissions');
  if (values.length < 2) return false;
  var data = values.slice(1);
  for (var i = 0; i < data.length; i++) {
    if (String(data[i][0]).trim() === role && String(data[i][1]).trim() === armId) {
      var v = data[i][2];
      return v === true || ['true', '1', 'да'].indexOf(String(v).toLowerCase()) !== -1;
    }
  }
  return false;
}

function validateRows(ss, rows, armId, role) {
  var values = _readSheetCached(ss, 'sys_parameters');
  var data = values.slice(1);
  var map = {};
  data.forEach(function (r) { map[String(r[0]).trim()] = { type: r[2], arm: String(r[4]).trim() }; });

  // Этапные АРМ (ARM_STAGE1..5) — агрегаторы полей из разных доменов, поэтому
  // строгая проверка «родной АРМ поля == armId пакета» для них ослаблена:
  // поле разрешено, если его родной allowedArm входит в множество доменов этапов.
  // ⚠ Инвариант: при удалении старых АРМ НЕ чистить allowedArm в
  // sys_parameters — здесь оно трактуется как классификатор ДОМЕНА поля.
  var isStageArm = /^ARM_STAGE\d+$/.test(String(armId));
  var STAGE_ALLOWED_DOMAINS = { 'ARM_PROJECT': true, 'ARM_OKS': true, 'ARM_WBS': true, 'ARM_TEP': true };

  // Field-level барьер на запись: для этапных АРМ роль может писать только те
  // поля, что разрешены ей в sys_role_fields (та же матрица, что фильтрует
  // видимость в getStageForm). ROLE_ADMIN → allowed=null (без ограничений).
  var allowed = isStageArm ? _roleAllowedCodes(ss, role) : null;

  for (var i = 0; i < rows.length; i++) {
    var code = rows[i].parameterCode;
    var def = map[code];
    if (!def) return 'Параметр «' + code + '» не зарегистрирован в sys_parameters';
    if (def.arm) {
      if (isStageArm) {
        if (!STAGE_ALLOWED_DOMAINS[def.arm]) {
          return 'Этапный АРМ «' + armId + '» не вправе писать «' + code + '» (домен ' + def.arm + ')';
        }
      } else if (def.arm !== armId) {
        return 'АРМ «' + armId + '» не вправе писать «' + code + '»';
      }
    }
    if (allowed && !allowed[code]) {
      return 'Роль ' + role + ' не вправе вносить параметр «' + code + '»';
    }
    var tErr = checkType(def.type, rows[i].value);
    if (tErr) return 'Параметр «' + code + '»: ' + tErr;
  }
  return null;
}

function checkType(type, value) {
  switch (String(type).toLowerCase()) {
    case 'number': return isNaN(Number(value)) ? 'ожидается число' : null;
    case 'date':   return isNaN(new Date(value).getTime()) ? 'ожидается дата' : null;
    default:       return null;
  }
}
