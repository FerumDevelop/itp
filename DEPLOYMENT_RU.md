# Развёртывание "итп" на Linux Kali для домена itp.site

## Подключение к серверу

```bash
ssh root@<IP-адрес-сервера>
```

## Установка Python и зависимостей

```bash
apt update
apt install python3 python3-pip python3-venv nginx git
```

## Клонирование проекта

```bash
mkdir -p /var/www
cd /var/www
git clone <URL-репозитория> itp
cd itp
```

## Создание виртуального окружения

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Настройка домена

Убедитесь, что домен `itp.site` указывает на IP вашего сервера (A-запись).

## Настройка Gunicorn

```bash
apt install gunicorn
```

Создайте systemd-сервис:

```bash
nano /etc/systemd/system/itp.service
```

Содержимое:

```ini
[Unit]
Description=ITP Social Network
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/itp
Environment="PATH=/var/www/itp/venv/bin"
ExecStart=/var/www/itp/venv/bin/gunicorn -w 3 -b 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

Запуск:

```bash
systemctl daemon-reload
systemctl start itp
systemctl enable itp
```

## Настройка Nginx

```bash
nano /etc/nginx/sites-available/itp
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
ln -s /etc/nginx/sites-available/itp /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

## Настройка SSL (Let's Encrypt)

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d itp.site -d www.itp.site
```

## Проверка работы

```bash
systemctl status itp
systemctl status nginx
```

Приложение будет доступно: http://itp.site

## Создание первого администратора

1. Зарегистрируйтесь на сайте
2. В файле `/var/www/itp/data/users.json` измените роль пользователя:
```json
"role": "creator"
```
3. Перезапустите:
```bash
systemctl restart itp
```

## Полезные команды

```bash
# Просмотр логов
journalctl -u itp -f

# Перезапуск
systemctl restart itp

# Остановка
systemctl stop itp
```

## Структура проекта на сервере

```
/var/www/itp/
├── app.py
├── config.py
├── requirements.txt
├── data/           # JSON файлы
├── uploads/        # Загруженные файлы
├── templates/      # Шаблоны
└── static/         # CSS, JS
```

## Резервное копирование

```bash
# Копирование данных
cp -r /var/www/itp/data /backup/itp_data_$(date +%Y%m%d)
```
