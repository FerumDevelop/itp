# Deployment Instructions for Windows Server with Domain итп.site

## Prerequisites

1. **Windows Server** (2016 or newer recommended)
2. **Python 3.9+** installed
3. **Domain** `итп.site` pointed to your server IP
4. **Administrator access** on the server

## Step 1: Install Required Software

### Install Python
1. Download Python 3.11 from https://python.org/downloads/
2. Run the installer
3. **Important**: Check "Add Python to PATH"
4. Click "Install Now"

### Install Git (optional, for cloning)
Download from https://git-scm.com/download/win

## Step 2: Set Up the Application

### Clone or Copy the Application
```cmd
cd C:\
mkdir itp
cd itp
git clone <your-repo-url> .
```
Or copy the entire project folder to `C:\itp`

### Create Virtual Environment
```cmd
cd C:\itp
python -m venv venv
venv\Scripts\activate
```

### Install Dependencies
```cmd
pip install -r requirements.txt
```

## Step 3: Configure Environment Variables

Create a `.env` file in `C:\itp`:
```
SECRET_KEY=your-super-secret-key-change-this
DEBUG=False
```

## Step 4: Set Up as Windows Service

### Install NSSM (Non-Sucking Service Manager)
Download from https://nssm.cc/download and extract, or install via chocolatey:
```cmd
choco install nssm
```

### Create the Service
```cmd
nssm install itp_site "C:\itp\venv\Scripts\python.exe" "C:\itp\app.py"
nssm set itp_site AppDirectory "C:\itp"
nssm set itp_site DisplayName "ITP Site"
nssm set itp_site Description "Social network itp.site"
nssm set itp_site Start SERVICE_AUTO_START
nssm set itp_site AppStdout "C:\itp\logs\stdout.log"
nssm set itp_site AppStderr "C:\itp\logs\stderr.log"
nssm set itp_site AppStdoutCreationDisposition 4
nssm set itp_site AppStderrCreationDisposition 4
nssm set itp_site AppRotateFiles 1
nssm set itp_site AppRotateOnline 1
nssm set itp_site AppRotateBytes 1048576
nssm set itp_site AppStdout "C:\itp\logs\service.log"
nssm set itp_site Iptables No
```

### Set Environment Variables in Service
```cmd
nssm set itp_site AppEnvironmentExtra SECRET_KEY=your-super-secret-key
nssm set itp_site AppEnvironmentExtra DEBUG=False
```

### Start the Service
```cmd
nssm start itp_site
```

## Step 5: Configure Reverse Proxy (Nginx or IIS)

### Option A: Using Nginx

1. Download Nginx from https://nginx.org/en/download.html
2. Extract to `C:\nginx`
3. Edit `C:\nginx\conf\nginx.conf`:

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
        alias C:/itp/static/;
    }
    
    location /uploads/ {
        alias C:/itp/uploads/;
    }
}
```

4. Start Nginx:
```cmd
C:\nginx\nginx.exe
```

### Option B: Using IIS (Internet Information Services)

1. Install IIS via Server Manager
2. Install URL Rewrite and Application Request Routing modules
3. Create a new Website in IIS:
   - Site name: `itp_site`
   - Physical path: `C:\itp`
   - Binding: `itp.site` on port 80
4. Add URL Rewrite rule for reverse proxy to `127.0.0.1:5000`

## Step 6: Configure SSL/HTTPS (Recommended)

### Using Let's Encrypt (Free)

1. Install Certbot from https://certbot.eff.org/
2. Run:
```cmd
certbot certonly --webroot -w C:\itp -d itp.site -d www.itp.site
```

3. Update Nginx config for HTTPS:
```nginx
server {
    listen 80;
    server_name itp.site www.itp.site;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name itp.site www.itp.site;
    
    ssl_certificate C:\Certbot\live\itp.site\fullchain.pem;
    ssl_certificate_key C:\Certbot\live\itp.site\privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static/ {
        alias C:/itp/static/;
    }
    
    location /uploads/ {
        alias C:/itp/uploads/;
    }
}
```

## Step 7: Firewall Configuration

1. Open Windows Defender Firewall
2. Allow inbound rules for:
   - Port 80 (HTTP)
   - Port 443 (HTTPS)
   - Port 5000 (if directly accessible)

## Step 8: Directory Permissions

Ensure the application directory has proper permissions:
```cmd
icacls C:\itp /grant Users:(OI)(CI)RX
icacls C:\itp\data /grant Users:(OI)(CI)RW
icacls C:\itp\uploads /grant Users:(OI)(CI)RW
icacls C:\itp\logs /grant Users:(OI)(CI)RW
```

## Step 9: Verify Installation

1. Check service status:
```cmd
nssm status itp_site
```

2. Check logs:
```cmd
type C:\itp\logs\service.log
```

3. Visit https://itp.site in your browser

## Maintenance Commands

### Restart Service
```cmd
nssm restart itp_site
```

### Stop Service
```cmd
nssm stop itp_site
```

### View Logs
```cmd
type C:\itp\logs\service.log
tail -f C:\itp\logs\service.log
```

### Update Application
```cmd
nssm stop itp_site
cd C:\itp
git pull
venv\Scripts\activate
pip install -r requirements.txt
nssm start itp_site
```

### Backup Data
```cmd
cd C:\itp
mkdir backups
python -c "import json; from pathlib import Path; data = json.load(open('data/users.json', 'r', encoding='utf-8')); json.dump(data, open(f'backups/users_{datetime.now().strftime(\"%Y%m%d\")}.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)"
```

## Troubleshooting

### Service won't start
1. Check Python path in NSSM
2. Verify virtual environment is set up correctly
3. Check logs for errors

### 502 Bad Gateway
1. Verify the Flask app is running on port 5000
2. Check Nginx error logs
3. Verify firewall settings

### Database Errors
1. Check JSON file permissions
2. Verify data directory exists
3. Check logs for specific errors

### Performance Issues
1. Increase worker processes in Nginx
2. Consider using a production WSGI server (Gunicorn)
3. Set up database caching

## Optional: Use Gunicorn for Better Performance

For production, consider using Gunicorn:
```cmd
pip install gunicorn
```

Update NSSM to run:
```
C:\itp\venv\Scripts\gunicorn.exe -w 4 -b 127.0.0.1:5000 app:app
```
