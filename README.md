# Asus Router Firmware Checker

Check for firmware updates on your schedule with no surprise auto-update disconnects mid-game.

A small Python CLI that logs into your ASUS router's web interface, asks ASUS servers if a newer firmware exists, and reports it alongside your current version.

## Usage

```bash
pip install -r requirements.txt
python3 firmware.py
```

You'll be prompted for:

- **Router IP** - Enter for `192.168.50.1`
- **Username** - Enter for `admin`
- **Password** - hidden input

Example output:

```
Current version: 3.0.0.6.102_40284-g167db18_1581-gca342_BB0B
Checking against ASUS servers...

A new firmware update is available: 3.0.0.6.102_40338-g47bdafb_1586-g1f414
Current version: 3.0.0.6.102_40284-g167db18_1581-gca342_BB0B
```

## How it works

The script drives the router's web interface the same way the browser UI does:

1. **Connect** - opens `Main_Login.asp` over HTTP, falling back to HTTPS (self-signed certificates are accepted).
2. **Log in** - reads the failed-login state embedded in the login page. If the router is locked out it stops without trying, since every attempt counts toward the lockout. Otherwise it asks for a captcha if needed, then logs in through `login_v2.cgi` with a nonce-salted SHA-256 of the credentials, so the password is never sent.
3. **Read the current version** - from the `firmver`, `buildno` and `extendno` NVRAM variables.
4. **Check for updates** - triggers `start_webs_update`, then polls until `webs_state_update` says the check finished. `webs_state_flag` says whether an update is available and `webs_state_info` holds its version.

In `firmware.py`, `Router` wraps the HTTP calls, while `log_in` and `check_asus_firmware_update` hold the flow.

## Notes

- Tested on RT-BE58U (firmware 3.0.0.6.x). The script has a marked spot where you can hook in notifications (Telegram bot, email, etc.).
- After 2 failed logins the router requires a captcha. The script opens the captcha image and asks you to type it. It never guesses, because each wrong answer counts as a failed login and 10 failures lock the router's web UI until a factory reset.
