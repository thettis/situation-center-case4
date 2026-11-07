#!/usr/bin/env python3
"""
CLI-прототип ситуационного центра — кейс 4.

Использование:
    python 04_прототип.py
    python 04_прототип.py --incidents incidents.csv --indicators indicators.csv

Что делает:
    читает indicators.csv, проверяет пороги, выводит alerts_out.csv,
    обрабатывает инциденты и переходы статусов.

TODO для команды:
    1. Дописать calc_severity() — 5 веток формулы из 02_правила.md.
    2. Дописать check_indicator() — правила A-1…A-5.
    3. Дописать deduplicate() — окно 5 минут.
    4. Дописать transition_incident() — допустимые и запрещённые переходы.
    5. Проверить на T4-1…T4-5.
"""
import csv
from datetime import datetime
import os
import sys
import hmac #для безопасности
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_CSV = os.path.join(BASE_DIR, "01_данные", "sites.csv")
INCIDENTS_CSV = os.path.join(BASE_DIR, "01_данные", "incidents.csv")
INDICATORS_CSV = os.path.join(BASE_DIR, "01_данные", "indicators.csv")
OUT_CSV = os.path.join(BASE_DIR, "alerts_out.csv")
AUDIT_CSV = os.path.join(BASE_DIR, "audit_out.csv") #для записи действий пользователей (аудит)
INCIDENTS_OUT_CSV = os.path.join(BASE_DIR, "incidents_out.csv")

OUT_FIELDS = ["alert_id", "at", "location", "indicator", "value", "severity", "action"]

ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"],
    "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"],
    "CLOSED": [],
}

ALLOWED_ROLES = {
    "NEW_ASSIGNED": ["dispatcher", "manager"],
    "ASSIGNED_IN_PROGRESS": ["engineer"],
    "ASSIGNED_CLOSED": ["manager"],
    "IN_PROGRESS_CLOSED": ["manager"],
}

def load_sites():
    """Прочитать sites.csv, вернуть set(site_id)."""
    active = set()
    try:
        with open(SITES_CSV, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                active.add(row["site_id"])
    except FileNotFoundError:
        print(f"WARN: {SITES_CSV} не найден", file=sys.stderr)
    return active


def calc_severity(value, norm_min, norm_max):
    """
    реализована формула из 02_правила.md:
      - value = "" → STALE
      - norm_min <= value <= norm_max → NORMAL
      - deviation_pct ≤ 10% → WARNING
      - deviation_pct > 10% → CRITICAL
    """
    if value == "" or value is None:
        return "STALE"
    v = float(value)
    lo, hi = float(norm_min), float(norm_max)
    if lo <= v <= hi:
        return "NORMAL"
    # ОБРАЗЕЦ — расчёт отклонения
    if v > hi:
        dev_pct = (v - hi) / hi * 100
    else:
        dev_pct = (lo - v) / lo * 100
    if dev_pct > 10:
        return "CRITICAL"
    return "WARNING"

SECRET_KEY = os.environ.get("SENSOR_SECRET", "test_prototype_key_123").encode() #сначала берем из переменной окружения, если нет — тестовый ключ
def verify_signature(row):
    """Проверяет, не подделал ли кто-то данные датчика."""
    #сбоорка данных в одну строку
    payload = f"{row['time']}|{row['location']}|{row['indicator']}|{row['value']}".encode()
    #генерация подписи HMAC
    expected_sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    #в таблице CSV нет параметра signature, поэтому для теста имитируем успешную проверку, если данные валидны.
    #по хорошему тут было бы return hmac.compare_digest(expected_sig, row["signature"])
    return True #заглушка для прототипа

def check_indicator(row, sites, seen, critical_counts):
    """
    реализованы A-1…A-5.
    Вернуть (severity, action) или None, или ("ERROR", code).
    """
    #проверка HMAC-подписи (защита от подмены)
    if not verify_signature(row):
        return ("ERROR", "SENSOR_SIGNATURE_INVALID")
    
    loc = row["location"]
    if loc not in sites:
        return ("ERROR", "UNKNOWN_LOCATION")

    sev = calc_severity(row["value"], row["norm_min"], row["norm_max"])
    if sev == "NORMAL":
        return None

    #дедупликация (A-5)
    key = (loc, row["indicator"])
    current_time = datetime.strptime(row["time"], "%Y-%m-%dT%H:%M:%SZ") 
    if key in seen:
        delta = (current_time - seen[key]).total_seconds() #считаем разницу в секундах
        if 0 <= delta < 300:
            return None  #повторное сообщение в пределах 5 минут игнорируем
    seen[key] = current_time

    # автоинцидент при 2 CRITICAL подряд (A-3)
    if sev == "CRITICAL":
        critical_counts[key] = critical_counts.get(key, 0) + 1
        if critical_counts[key] >= 2:
            print(f"!!! АВТОИНЦИДЕНТ: Датчик {key} выдал 2 CRITICAL подряд!")
            #имитация INSERT в БД (запись в incidents_out.csv)
            #генерация ID на основе времени и локации для уникальности
            inc_id = f"inc_auto_{row['time'].replace(':', '').replace('-', '')}_{loc}"
            
            with open(INCIDENTS_OUT_CSV, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if f.tell() == 0: #если файл только что создан, добавить заголовок
                    w.writerow(["incident_id", "type", "location", "time", "responsible", "status", "deadline", "source"])
                w.writerow([inc_id, row["indicator"], loc, row["time"], "", "NEW", "2025-11-02T23:59:59Z", "auto"])
                
            critical_counts[key] = 0  #сбрасываем после создания
    
    #эскалация STALE (A-4)
    action = "ESCALATED" if sev in ("CRITICAL", "STALE") else "ALERT_CREATED"
    return (sev, action)


def write_alert(alert):
    new_file = not os.path.exists(OUT_CSV)
    with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        if new_file:
            w.writeheader()
        w.writerow(alert)


def transition_incident(incident, to_status, actor_role, responsible=None, resolution_reason=None):
    """
    TODO: проверить допустимость перехода через ALLOWED_TRANSITIONS.
    Вернуть (True, None) или (False, "INVALID_TRANSITION").
    """
    current = incident["status"]
    #существует ли такой переход в принципе
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return (False, "INVALID_TRANSITION")
        
    #проверка, что роль actor_role имеет право на этот переход
    transition_key = f"{current}_{to_status}"
    allowed_roles_for_this = ALLOWED_ROLES.get(transition_key, [])
    if actor_role not in allowed_roles_for_this:
        return (False, "FORBIDDEN")
        
    #проверка на обязательное условие для закрытия (resolution_reason)
    if to_status == "CLOSED":
        if not resolution_reason:
            return (False, "RESOLUTION_REASON_REQUIRED")
        #если закрываем из ASSIGNED (ложный вызов), то причина должна быть "NO_ACTION"
        if current == "ASSIGNED" and resolution_reason != "NO_ACTION":
            return (False, "INVALID_RESOLUTION_REASON")
    
    incident["status"] = to_status #замена статуса объекту
    if responsible:
        incident["responsible"] = responsible #записать ответственного

    #записываем в аудит
    audit_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    inc_id = incident.get("incident_id", "unknown")
    
    #определяет тип действия для аудита
    if to_status == "ASSIGNED":
        action_type = "assigned"
    elif to_status == "CLOSED":
        action_type = "closed"
    else:
        action_type = "status_changed"

    with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        #если файл пустой, добавить заголовок
        if f.tell() == 0:
            w.writerow(["action", "incident_id", "actor", "at", "from_status", "to_status", "reason"])
        #пишем строку
        w.writerow([action_type, inc_id, actor_role, audit_time, current, to_status, resolution_reason or ""])

    #если все проверки пройдены    
    return (True, None)


def main():
    #удаление старых файлов перед запуском
    if os.path.exists(OUT_CSV):
        os.remove(OUT_CSV)
    if os.path.exists(AUDIT_CSV):
        os.remove(AUDIT_CSV)
    if os.path.exists(INCIDENTS_OUT_CSV):
        os.remove(INCIDENTS_OUT_CSV)
    
    incidents_path = INCIDENTS_CSV
    indicators_path = INDICATORS_CSV
    if "--incidents" in sys.argv:
        incidents_path = sys.argv[sys.argv.index("--incidents") + 1]
    if "--indicators" in sys.argv:
        indicators_path = sys.argv[sys.argv.index("--indicators") + 1]

    sites = load_sites()
    if not sites:
        print("❌ sites.csv пуст или не найден")
        sys.exit(2)

    alerts = 0
    seen = {}
    critical_counts = {}

    with open(indicators_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    #сортировка данных по времени, чтобы дедупликация и автоинциденты работали верно
    rows.sort(key=lambda x: x["time"])

    for row in rows:
        result = check_indicator(row, sites, seen, critical_counts)
        if result is None:
            continue
        severity, action = result
        if severity == "ERROR":
            print(f"❌ {row['location']}: {action}")
            continue
        alert = {
            "alert_id": f"alrt_{alerts + 1:04d}",
            "at": row["time"],
            "location": row["location"],
            "indicator": row["indicator"],
            "value": row["value"],
            "severity": severity,
            "action": action,
        }
        write_alert(alert)
        alerts += 1

    #проверить переходы на incidents.csv
    with open(incidents_path, encoding="utf-8") as f:
        incs = list(csv.DictReader(f))
    # --- ВАЛИДАЦИЯ ИНЦИДЕНТОВ (T4-3) ---
    inc_errors = 0
    for inc in incs:
        if inc["location"] not in sites:
            print(f"❌ Инцидент {inc['incident_id']}: {inc['location']} - UNKNOWN_LOCATION")
            inc_errors += 1
    if inc_errors == 0:
        print("OK: все инциденты имеют валидный location")

    print(f"OK: indicators обработано: {len(rows)}")
    print(f"    алертов создано:       {alerts}")
    print(f"    incidents загружено:   {len(incs)}")
    print(f"    файл: {OUT_CSV}")

    print("\n--- ДЕМОНСТРАЦИЯ T4-1 (СОЗДАНИЕ И НАЗНАЧЕНИЕ) ---")
    # 1. Имитируем создание инцидента inc_001 (изначально NEW, без ответственного)
    test_inc = {"incident_id": "inc_001", "status": "NEW", "responsible": ""}
    # Запись в аудит о том, что инцидент создан (как требует T4-1)
    with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if f.tell() == 0: # если файла не было
            w.writerow(["action", "incident_id", "actor", "at", "from_status", "to_status", "reason"])
        w.writerow(["incident_created", "inc_001", "dispatcher", datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"), "", "NEW", ""])
    print(f"1. Инцидент inc_001 создан. Статус: {test_inc['status']}")
    # 2. Диспетчер назначает ответственного e_101 (переход NEW -> ASSIGNED)
    res = transition_incident(
        incident=test_inc, 
        to_status="ASSIGNED", 
        actor_role="dispatcher", 
        responsible="e_101"
    )
    print(f"2. Попытка диспетчера назначить e_101: {res}")
    print(f"   Итоговый статус: {test_inc['status']}")
    print(f"   Итоговый ответственный: {test_inc['responsible']}")

if __name__ == "__main__":
    main()