import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import string
import tempfile
import time
import webbrowser
from pathlib import Path

import requests
import urllib3

# login_info error_status values, taken from the router's Main_Login.asp
ERROR_INVALID_CREDENTIALS = 3
ERROR_TEMPORARILY_LOCKED = 7
ERROR_WRONG_CAPTCHA = 10
ERROR_PERMANENTLY_LOCKED = 11

def create_session(ip):
    # Try plain HTTP first, fall back to HTTPS if the router requires it
    for scheme in ("http", "https"):
        base_url = f"{scheme}://{ip}"
        session = requests.Session()
        session.headers.update({"Referer": f"{base_url}/Main_Login.asp"})
        if scheme == "https":
            # Router admin interfaces usually have a self-signed certificate
            session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            # The router refuses to log in unless the login page was requested first
            session.get(f"{base_url}/Main_Login.asp", timeout=10)
            return session, base_url
        except requests.exceptions.RequestException:
            session.close()
    return None, None

def get_login_state(session, base_url):
    # The login page embeds the router's failed-login state, e.g.
    # { "lock_time": 194, "error_status": 10, "error_num": 2, ... },
    # and whether the login captcha is enabled at all
    html = session.get(f"{base_url}/Main_Login.asp", timeout=10).text
    match = re.search(r"var login_info = tryParseJSON\('(.*?)'\);", html)
    login_info = json.loads(match.group(1)) if match else {}
    match = re.search(r"var captcha_enable = htmlEnDeCode\.htmlEncode\(decodeURIComponent\('(\d*)'\)\)", html)
    captcha_enabled = match.group(1) != "0" if match else True
    return login_info, captcha_enabled

def random_string(length):
    alphabet = string.digits + string.ascii_letters
    return "".join(secrets.choice(alphabet) for _ in range(length))

def ask_for_captcha(session, base_url):
    # The router shows a captcha after 2 failed logins. Guessing it automatically
    # is not worth it: every wrong answer counts as a failed login, and after 10
    # the router locks the web UI until a factory reset
    image = session.get(f"{base_url}/captcha.gif", timeout=10).content
    with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as f:
        f.write(image)
    captcha_path = Path(f.name)
    try:
        print("The router requires a captcha because of previous failed logins.")
        print(f"Captcha image: {captcha_path}")
        webbrowser.open(captcha_path.as_uri())
        return input("Captcha text: ").strip()
    finally:
        os.remove(captcha_path)

def login(session, base_url, username, password, captcha):
    # Same flow as the web UI: get a one-time nonce, then send a salted SHA-256
    # of the credentials instead of the password itself
    nonce_id = random_string(10)
    nonce = session.post(f"{base_url}/get_Nonce.cgi", json={"id": nonce_id}, timeout=10).json()["nonce"]
    cnonce = random_string(32)
    login_data = {
        "group_id": "",
        "action_mode": "",
        "action_script": "",
        "action_wait": "5",
        "current_page": "Main_Login.asp",
        "next_page": "",
        "login_authorization": hashlib.sha256(f"{username}:{nonce}:{password}:{cnonce}".encode()).hexdigest(),
        "id": nonce_id,
        "cnonce": cnonce,
        "login_captcha": base64.b64encode(captcha.encode()).decode(),
    }
    session.post(f"{base_url}/login_v2.cgi", data=login_data, timeout=10).raise_for_status()
    # On success the router sets an asus_token cookie
    return bool(session.cookies.get("asus_token"))

def describe_login_failure(login_info):
    status = login_info.get("error_status")
    if status == ERROR_INVALID_CREDENTIALS:
        message = "Login failed - invalid username or password."
    elif status == ERROR_TEMPORARILY_LOCKED:
        message = (f"Login is locked after 5 failed attempts. "
                   f"Try again in {login_info.get('lock_time', 0)} seconds.")
    elif status == ERROR_WRONG_CAPTCHA:
        message = "Login failed - the captcha was wrong."
    elif status == ERROR_PERMANENTLY_LOCKED:
        message = ("The router locked its web login after 10 failed attempts. "
                   "It has to be reset to factory settings to unlock it.")
    else:
        message = f"Login failed (router error status {status!r})."
    if login_info.get("last_time_lock_warning") and status != ERROR_PERMANENTLY_LOCKED:
        message += ("\nWarning: one more failed attempt will lock the router until "
                    "it is reset to factory settings.")
    return message

def nvram_get(session, base_url, key):
    # This firmware only returns the first key when multiple hooks are passed
    # to appGet.cgi, so request one key at a time
    resp = session.get(f"{base_url}/appGet.cgi?hook=nvram_get({key})", timeout=10)
    return resp.json().get(key, "")

def check_asus_firmware_update(ip, username, password):
    session, base_url = create_session(ip)
    if not session:
        print(f"Could not connect to the router at {ip} (tried both HTTP and HTTPS).")
        return

    try:
        # Step 1: Log in to the router. Do not even try while it is locked out,
        # since every attempt counts toward the permanent lockout
        login_info, captcha_enabled = get_login_state(session, base_url)
        if login_info.get("error_status") in (ERROR_TEMPORARILY_LOCKED, ERROR_PERMANENTLY_LOCKED):
            print(describe_login_failure(login_info))
            return

        captcha = ""
        if captcha_enabled and login_info.get("error_num", 0) >= 2:
            captcha = ask_for_captcha(session, base_url)

        if not login(session, base_url, username, password, captcha):
            login_info, _ = get_login_state(session, base_url)
            print(describe_login_failure(login_info))
            return

        # Current version details, e.g. 3.0.0.6.102_40284-g167db18_1581-gca342_BB0B
        firmver = nvram_get(session, base_url, "firmver")
        buildno = nvram_get(session, base_url, "buildno")
        extendno = nvram_get(session, base_url, "extendno")
        current_version = f"{firmver}.{buildno}_{extendno}".strip("._")
        print(f"Current version: {current_version}")

        # Step 2: Send a command to start the update check against ASUS servers
        check_data = {
            "action_mode": "apply",
            "action_script": "start_webs_update",
            "action_wait": "0"
        }
        session.post(f"{base_url}/apply.cgi", data=check_data, timeout=10)

        # Step 3: Poll for the result. webs_state_update turns "1" once the check
        # has finished (it does not mean an update exists). webs_state_flag is
        # "1" (or "2" for a forced update) when a newer firmware is available, and
        # webs_state_info holds the latest version string the web UI shows
        print("Checking against ASUS servers...")
        check_done = False
        error = ""
        for _ in range(12):
            time.sleep(5)
            check_done = nvram_get(session, base_url, "webs_state_update").strip() == "1"
            error = nvram_get(session, base_url, "webs_state_error").strip()
            if check_done or (error and error != "0"):
                break
        latest_version = nvram_get(session, base_url, "webs_state_info").strip()
        update_flag = nvram_get(session, base_url, "webs_state_flag").strip()

        # webs_state_info looks like "3006_102_40338-g47bdafb_1586-g1f414":
        # strip the leading firmware digits to get the build number ("102_40338"),
        # then rebuild the dotted display format the web UI uses
        latest_display = latest_version
        if latest_version:
            head, _, suffix = latest_version.partition("-")
            firm_digits = firmver.replace(".", "")
            latest_build = head[len(firm_digits) + 1:] if head.startswith(firm_digits + "_") else head
            latest_display = f"{firmver}.{latest_build}-{suffix}" if suffix else latest_version

        print()
        if error and error != "0":
            print(f"The router failed to reach the ASUS update servers (error code {error}).")
        elif not check_done:
            print("Timed out waiting for the router to finish checking for updates.")
        elif update_flag in ("1", "2"):
            print(f"A new firmware update is available: {latest_display}")
            print(f"Current version: {current_version}")
            # Here you can add code to send a notification (e.g., via a Telegram Bot or SMTP email)
        else:
            print("No firmware update currently available. The system is up to date.")

    except requests.exceptions.RequestException as e:
        print(f"Communication error with the router: {e}")

if __name__ == "__main__":
    ROUTER_IP = input("Router IP (Enter for '192.168.50.1'): ").strip() or "192.168.50.1"
    USERNAME = input("Username (Enter for 'admin'): ").strip() or "admin"
    PASSWORD = getpass.getpass("Password: ")

    check_asus_firmware_update(ROUTER_IP, USERNAME, PASSWORD)
