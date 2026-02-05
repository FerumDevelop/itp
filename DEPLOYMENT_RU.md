# Инструкция по развёртыванию социальной сети "итп"

## Требования

1. **Python 3.9+** (скачать с python.org)
2. **Операционная система**: Windows, Linux или macOS
3. **Веб-сервер**: Nginx или Gunicorn (для production)
4. **Домен** (опционально):指向 вашему серверу

## Установка на Windows

### Шаг 1: Установка Python

1. Скачайте Python 3.11 с https://python.org/downloads/
2. Запустите установщик
3. **Важно**: Отметьте "Add Python to PATH"
4. Нажмите "Install Now"

### Шаг 2: Копирование проекта

Скопируйте папку проекта в `C:\itp`

### Шаг 3: Создание виртуального окружения

```cmd
cd C:\itp
python -m venv venv
venv\Scripts\activate
```

### Шаг 4: Установка зависимостей

```cmd
pip install -r requirements.txt
```

### Шаг 5: Настройка переменных окружения

Создайте файл `.env` в папке `C:\itp`:

```
SECRET_KEY=ваш-секретный-ключ-измените-в-production
DEBUG=False
```

### Шаг 6: Запуск в режиме разработки

```cmd
python app.py
```

Приложение будет доступно по адресу http://localhost:5000

## Установка на Linux (Ubuntu/Debian)

### Шаг 1: Установка Python и зависимостей

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nginx git
```

### Шаг 2: Клонирование и настройка проекта

```bash
sudo mkdir -p /var/www/itp
sudo chown $USER:$USER /var/www/itp
cd /var/www/itp
git clone <url-репозитория> .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Шаг 3: Настройка Gunicorn

```bash
sudo nano /etc/systemd/system/itp.service
```

Содержимое файла:

```ini
[Unit]
Description=ITP Social Network
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/itp
Environment="PATH=/var/www/itp/venv/bin"
ExecStart=/var/www/itp/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

Запуск сервиса:

```bash
sudo systemctl daemon-reload
sudo systemctl start itp
sudo systemctl enable itp
```

### Шаг 4: Настройка Nginx

```bash
sudo nano /etc/nginx/sites-available/itp
```

Содержимое:

```nginx
server {
    listen 80;
    server_name itp.site www.itp.site;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /var/www/itp/static/;
    }

    location /uploads/ {
        alias /var/www/itp/uploads/;
    }
}
```

Активация:

```bash
sudo ln -s /etc/nginx/sites-available/itp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Настройка SSL/HTTPS (Let's Encrypt)

### На Linux:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d itp.site -d www.itp.site
```

### На Windows:

1. Скачайте Certbot с https://certbot.eff.org/
2. Получите сертификат:

```cmd
certbot certonly --webroot -w C:\itp -d itp.site -d www.itp.site
```

3. Обновите конфигурацию Nginx для использования HTTPS

## Структура проекта

```
itp/
├── app.py              # Главный файл приложения
├── config.py           # Конфигурация
├── requirements.txt     # Зависимости Python
├── data/               # JSON файлы данных
│   ├── users.json
│   ├── posts.json
│   ├── comments.json
│   ├── reactions.json
│   ├── applications.json
│   ├── bans.json
│   ├── subscriptions.json
│   ├── notifications.json
│   └── admin_logs.json
├── uploads/            # Загруженные файлы
│   ├── avatars/
│   ├── banners/
│   ├── post_media/
│   └── application_media/
├── templates/          # HTML шаблоны
│   ├── base.html
│   ├── index.html
│   ├── post.html
│   ├── profile/
│   ├── auth/
│   ├── admin/
│   ├── errors/
│   └── ...
└── static/             # Статические файлы
    ├── css/
    └── js/
```

## Команды управления

### Linux (systemd):

```bash
# Просмотр статуса
sudo systemctl status itp

# Перезапуск
sudo systemctl restart itp

# Просмотр логов
sudo journalctl -u itp -f
```

### Windows (NSSM):

```cmd
# Статус
nssm status itp

# Перезапуск
nssm restart itp

# Просмотр логов
type C:\itp\logs\service.log
```

## Устранение неполадок

1. **Ошибка 500 при запуске**:
   - Проверьте логи: `logs/error.log`
   - Убедитесь, что все папки созданы

2. **Файлы не загружаются**:
   - Проверьте права на папку `uploads/`
   - Убедитесь, что папки `avatars`, `banners`, `post_media` существуют

3. **Ошибки подключения к базе**:
   - Проверьте, что JSON файлы существуют в папке `data/`
   - Убедитесь, что формат JSON корректный

## Создание первого администратора

После запуска приложения:
1. Зарегистрируйте нового пользователя
2. Вручную измените роль пользователя в файле `data/users.json` на `"creator"` или `"admin"`
3. Перезапустите приложение

## Производительность

- Для production используйте Gunicorn + Nginx
- Настройте кэширование в Nginx
- Регулярно создавайте резервные копии папки `data/`

## Мониторинг

- Логи приложения: `logs/app.log`
- Логи доступа Nginx: `/var/log/nginx/access.log`
- Логи ошибок Nginx: `/var/log/nginx/error.log`

## Безопасность

1. Используйте сложный SECRET_KEY
2. Включите HTTPS в production
3. Регулярно обновляйте зависимости
4. Создавайте резервные копии данных
5. Ограничьте доступ к папке `data/`
