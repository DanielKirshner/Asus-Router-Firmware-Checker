# Asus Router Firmware Checker

Check for firmware updates on your schedule with no surprise auto-update disconnects mid-game.

A small Python CLI that logs into your ASUS router's web interface, asks ASUS servers if a newer firmware exists, and compares it against your current version.

## Usage

```bash
pip install -r requirements.txt
python3 firmware.py
```

You'll be prompted for:

- **Router IP** — Enter for `192.168.50.1`
- **Username** — Enter for `admin`
- **Password** — hidden input

Example output:

```
Current version: 3.0.0.6.102_40284-g167db18_1581-gca342_BB0B
Checking against ASUS servers...

A new firmware update is available: 3.0.0.6.102_40338-g47bdafb_1586-g1f414
```

## Notes

- Tested on RT-BE58U (firmware 3.0.0.6.x). The script has a marked spot where you can hook in notifications (Telegram bot, email, etc.).
