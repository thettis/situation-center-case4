import csv
import hmac
import hashlib

# Тот же самый ключ, что и в прототипе
SECRET_KEY = b"test_prototype_key_123"

def generate_sig(time, loc, ind, val):
    payload = f"{time}|{loc}|{ind}|{val}".encode()
    return hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()

# 1. Валидные данные (подпись сгенерирована правильно)
t1, l1, i1, v1 = "2025-11-03T10:00:00Z", "site_01", "temperature", "25.0"
sig1 = generate_sig(t1, l1, i1, v1)

# 2. Подмененные данные (хакер изменил значение на 100, а подпись оставил старую)
t2, l2, i2, v2 = "2025-11-03T10:05:00Z", "site_02", "humidity", "60.0"
sig2 = generate_sig(t2, l2, i2, v2) 
v2_tampered = "100.0" # <--- Хакер подменил значение!

with open("test_hmac.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["time", "location", "indicator", "value", "norm_min", "norm_max", "status", "signature"])
    # Валидная строка
    w.writerow([t1, l1, i1, v1, "20.0", "26.0", "NORMAL", sig1])
    # Подмененная строка
    w.writerow([t2, l2, i2, v2_tampered, "40.0", "70.0", "CRITICAL", sig2])

print("Файл test_hmac.csv успешно создан!")