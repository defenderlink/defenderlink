<<<<<<< HEAD
# DefenderLink — Полный MVP

Сервис проверки ссылок и файлов на фишинг/вредоносное ПО (Google Safe Browsing, VirusTotal, PhishTank, OpenPhish).
Хостинг: **Netlify**. Домен: `defenderlink.app` (GoDaddy).

## ⚙️ Возможности
- Проверка URL: Google Safe Browsing, VirusTotal, PhishTank, OpenPhish
- Проверка файлов: VirusTotal (загрузка + получение отчёта)
- Готовые Netlify Functions, CORS, UI на чистом HTML/CSS/JS

---

## 📁 Структура
```
defenderlink/
├── netlify.toml
├── package.json
├── .gitignore
├── src/
│   ├── index.html
│   └── script.js
└── netlify/
    └── functions/
        ├── check-url.js
        └── check-file.js
```

---

## 🚀 Быстрый старт (локально)
1) Установите зависимости:
```bash
npm install
```

2) Войдите в Netlify и запустите локально:
```bash
npx netlify login
npm run dev
```
Откроется `http://localhost:8888` с проксированием функций.

3) Настройте переменные окружения **в Netlify (или локально)**:
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_SAFE_BROWSING_KEY`
- *(опционально)* `PHISHTANK_API_KEY`

Локально можно экспортировать переменные перед запуском или использовать `netlify env:set`:
```bash
npx netlify env:set VIRUSTOTAL_API_KEY "ВАШ_КЛЮЧ"
npx netlify env:set GOOGLE_SAFE_BROWSING_KEY "ВАШ_КЛЮЧ"
# npx netlify env:set PHISHTANK_API_KEY "ВАШ_КЛЮЧ"
```

---

## ☁️ Деплой на Netlify
1) Создайте новый репозиторий и запушьте код:
```bash
git init
git add .
git commit -m "DefenderLink MVP"
git branch -M main
git remote add origin https://github.com/defenderlink/defenderlink.git
git push -u origin main
```

2) В Netlify: **Add new site → Import from Git** → выберите репозиторий.

3) В Netlify → **Site settings → Environment variables** добавьте ключи API:
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_SAFE_BROWSING_KEY`
- *(опционально)* `PHISHTANK_API_KEY`

4) Домен: привяжите `defenderlink.app` → включите **HTTPS** (автоматический сертификат).

---

## 🧠 Важно знать (ограничения/API)
- **VirusTotal (v2)**: бесплатный тариф — ограничение по запросам; отчёт может готовиться несколько секунд.
  - Функция опрашивает отчёт до ~10 секунд суммарно. Если отчёт не готов — статус `warning` с permalink.
- **Google Safe Browsing**: требуется валидный API-ключ и включённый API в GCP.
- **PhishTank**: API бывает нестабильным; если упал — UI покажет предупреждение.
- **OpenPhish**: используется публичный feed, сравнение по полному URL (нормализовано).

---

## 🔒 Безопасность
- Ключи **не** вшиваются во фронтенд; все запросы идут через Netlify Functions.
- Включены CORS-заголовки и базовые security-заголовки в `netlify.toml`.
- При необходимости ограничьте источники: замените `Access-Control-Allow-Origin: *` на свой домен.

---

## 🎨 Интеграция с Webflow
- Можно экспортировать HTML/CSS из Webflow и заменить содержимое `src/index.html` и стили.
- Скрипт `src/script.js` оставьте подключённым: он вызывает Netlify Functions (`/.netlify/functions/...`).

---

## 🪓 Траблшутинг
- **405 Method Not Allowed**: проверьте метод и путь (`/.netlify/functions/check-url`/`check-file`).
- **CORS ошибка**: убедитесь, что и в функциях, и в `netlify.toml` есть CORS-заголовки.
- **GSB ошибка**: проверьте, включён ли Safe Browsing API и ключ корректный.
- **VirusTotal no report**: подождите 5–10 секунд и повторите; проверьте ссылку `permalink` в ответе.

Удачного релиза! 🚀
=======
# DefenderLink — Netlify Functions Backend

## Env vars (Netlify → Site settings → Environment)
- `VIRUSTOTAL_API_KEY` (required)
- `GOOGLE_SAFE_BROWSING_KEY` (recommended)

## Endpoints
- POST `/api/check-url` → `{ "url": "https://example.com" }`
- POST `/api/check-file` → raw bytes with `Content-Type: application/octet-stream`

## Notes
- OpenPhish/PhishTank used as public feeds; may be rate-limited.
- DNS/HEAD heuristics included; WHOIS only for report.
>>>>>>> 5fd1a73e7c785353bb4c6313239887405cef94c3
