# License Activation Service

Сервис активации лицензии: клиент шифрует данные устройства AES-256-SIV, сервер расшифровывает токен, проверяет checksum и сохраняет лицензию в Postgres. Одна лицензия — одно устройство.

## Структура

- `client/` — CLI, собирает параметры устройства и отправляет токен на сервер
- `server/` — FastAPI, Postgres и Docker Compose

## Быстрый старт

Ключ сначала создаёт клиент, сервер затем берёт его из `client/.env`.

```bash
cd client
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python generate_env.py

cd ../server
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python generate_env.py
docker compose up --build -d

curl http://127.0.0.1:8000/health
```

Ответ: `{"status":"ok"}`.

## Активация

Через клиент:

```bash
cd client
.venv/bin/python main.py ABCD-EFGH-IJKL-MNOP
```


Тело можно передать и в JSON:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/licenses/activate \
  -H 'Content-Type: application/json' \
  -d "{\"payload\": \"$TOKEN\"}"
```

Ответ:

```json
{
  "status": "activated",
  "already_activated": false,
  "activation_id": "53527204-6cbc-4d81-a878-9314f2542160",
  "license": "ABCD-EFGH-IJKL-MNOP",
  "activated_at": "2026-11-24T12:00:08.276628Z"
}
```

Коды ответа:

| Код | Значение |
| --- | --- |
| `200` | активация выполнена или уже была (идемпотентный повтор) |
| `400` | неверный base64/токен или JSON |
| `409` | лицензия уже активирована на другом устройстве |
| `413` | тело слишком большое |
| `415` | неверный `Content-Type` |
| `422` | checksum не совпал или неверные поля payload |

## Как это работает

- `DEVICE_ENCRYPTION_KEY` — общий для клиента и сервера ключ на 64 байта;
- payload сериализуется в канонический JSON (`sort_keys=True`, разделители `,` и `:`), шифруется через AES-256-SIV и кодируется в base64;
- `checksum` — SHA-256 от канонического JSON первых восьми полей;
- `device_fingerprint` — SHA-256 от MAC-адреса в нижнем регистре;
- повтор той же лицензии с тем же MAC возвращает `200` с `already_activated: true`;
- та же лицензия с другим MAC возвращает `409`;
- таблица создаётся автоматически при старте приложения (`Base.metadata.create_all`).

## Postgres

```bash
cd server
docker compose exec db psql -U license -d license -c 'SELECT * FROM licenses;'
docker compose down       # остановить
docker compose down -v    # остановить и удалить данные
```

Порт Postgres наружу не проброшен — подключение только через `docker compose exec db`.

## Переменные окружения

- `client/.env`: `DEVICE_ENCRYPTION_KEY`, `LICENSE_SERVER_URL`, `LICENSE_TIMEOUT`
- `server/.env`: `DEVICE_ENCRYPTION_KEY`, `DATABASE_URL`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`

Файлы `.env` в git не попадают. `server/generate_env.py` копирует ключ из `client/.env`, поэтому клиентский `.env` должен существовать первым. В Docker Compose `DATABASE_URL` переопределяется на хост `db`, а не `localhost`.
