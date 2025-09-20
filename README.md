# Splunk Field Redactor
> Because it's lame to redact manualy fields.

This is a simple splunk app that redact fields bases on pattern reconaisance:
- IPv4 & IPv4
- Domain
- URL
- Telephone number
- Username
- Full name
- Email

## Usage

Select the fields to be redacted:
```splunk
index="*" 
| table AdresseIP, email, username, hostname
| redact fields="AdresseIP, email, username, hostname"
```

The result should look like

| _time                   | URL                                     | Destination_IP  | Domain                  | E-mail                           | Full_Name      | Source_IP      | Telephone         |
| ----------------------- | --------------------------------------- | --------------- | ----------------------- | -------------------------------- | -------------- | -------------- | ----------------- |
| 20/09/2025 18:07:06,000 | http://daXXXXXXXXXXXXXXX.io/steal.php   | 198.51.XXX.77   | daXXXXXXXXXXXXXXX.io    | X.muXXXXX@daXXXXXXXXXXXXXXX.io   | HaXXXXXXXXX    | 10.10.XXX.9    | +XX-3X-1XXXXXXX   |
| 20/09/2025 18:07:06,000 | https://faXXXXXXXXX.info/update.apk     | 203.0.XXX.99    | faXXXXXXXXX.info        | clXXXX.duXXXX@faXXXXXXXXX.info   | ClXXXX DuXXXX  | 192.168.XXX.12 | +XX-1-4X-5X-6X-7X |
| 20/09/2025 18:07:06,000 | http://suXXXXXXXXXXXXXXXXXX.ru/file.exe | 185.199.XXX.133 | suXXXXXXXXXXXXXXXXXX.ru | X.ivXXXX@suXXXXXXXXXXXXXXXXXX.ru | SeXXXX IvXXXX  | 172.16.XXX.77  | +X-4XX-1XX-4XXX   |
| 20/09/2025 18:07:06,000 | https://phXXXXXXXXXX.org/account-reset  | 198.51.XXX.42   | phXXXXXXXXXX.org        | ejXXXXXX@phXXXXXXXXXX.org        | EmXXX JoXXXXX  | 10.0.XXX.23    | +XX-2X-7XXX-0XXX  |
| 20/09/2025 18:07:06,000 | http://maXXXXXXXXXXXXX.net/login        | 203.0.XXX.17    | maXXXXXXXXXXXXX.net     | X.tuXXXX@maXXXXXXXXXXXXX.net     | MiXXXXX TuXXXX | 192.168.XXX.45 | +X-2XX-5XX-0XXX   |


## SetUp
### Script
Place the script in `/opt/splunk/etc/apps/<app name>/bin/redactor.py`
### Packages
In the app folder:
```bash
pip3 install --target=./lib -r requirements.txt
```

### Command.conf
In `/opt/splunk/etc/apps/<app name>/default`
```toml
[redact]
python.version = python3
chunked = true
filename = redactor.py
```

