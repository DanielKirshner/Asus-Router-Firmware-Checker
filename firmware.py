"""Check an ASUS router for firmware updates without letting it auto-update.

The script talks to the router's web interface the same way the browser UI
does: it logs in, asks the router to check the ASUS update servers, waits for
the check to finish, and reports whether a newer firmware is available.
"""

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
from dataclasses import dataclass
from pathlib import Path

import requests
import urllib3

REQUEST_TIMEOUT = 10

# login_info error_status values, taken from the router's Main_Login.asp
ERROR_INVALID_CREDENTIALS = 3
ERROR_TEMPORARILY_LOCKED = 7
ERROR_WRONG_CAPTCHA = 10
ERROR_PERMANENTLY_LOCKED = 11

# The router asks for a captcha once this many logins have failed in a row
CAPTCHA_AFTER_FAILED_LOGINS = 2

# How long to wait for the router to finish checking the ASUS servers
UPDATE_POLL_INTERVAL = 5
UPDATE_POLL_ATTEMPTS = 12


@dataclass
class LoginState:
    """Failed-login state the router embeds in its login page."""

    error_status: int | str
    error_num: int
    lock_time: int
    last_time_lock_warning: bool
    captcha_enabled: bool

    @property
    def is_locked(self):
        """True while the router refuses all logins."""
        return self.error_status in (ERROR_TEMPORARILY_LOCKED, ERROR_PERMANENTLY_LOCKED)

    @property
    def needs_captcha(self):
        """True when the next login must include the captcha text."""
        return self.captcha_enabled and self.error_num >= CAPTCHA_AFTER_FAILED_LOGINS


@dataclass
class FirmwareVersion:
    """The firmware currently installed on the router."""

    firmver: str  # e.g. "3.0.0.6"
    buildno: str  # e.g. "102"
    extendno: str  # e.g. "40338-g47bdafb_1586-g1f414_BB0B"

    def __str__(self):
        """Full version as the web UI shows it, e.g. 3.0.0.6.102_40338-g47bdafb_1586-g1f414_BB0B."""
        return f"{self.firmver}.{self.buildno}_{self.extendno}".strip("._")

    def format_latest(self, latest_version):
        """Convert the router's webs_state_info value to the web UI's dotted format.

        webs_state_info looks like "3006_102_40338-g47bdafb_1586-g1f414": strip
        the leading firmware digits to get the build number ("102_40338"), then
        prepend the dotted firmware version ("3.0.0.6.102_40338-g47bdafb_1586-g1f414").
        """
        if not latest_version:
            return latest_version
        head, _, suffix = latest_version.partition("-")
        firm_digits = self.firmver.replace(".", "")
        latest_build = head[len(firm_digits) + 1:] if head.startswith(firm_digits + "_") else head
        return f"{self.firmver}.{latest_build}-{suffix}" if suffix else latest_version


@dataclass
class UpdateCheckResult:
    """Outcome of asking the router to check the ASUS update servers."""

    finished: bool
    error: str  # webs_state_error; "" or "0" means no error
    update_available: bool
    latest_version: str  # raw webs_state_info value

    @property
    def failed(self):
        """True when the router could not reach the ASUS update servers."""
        return self.error not in ("", "0")


class Router:
    """An HTTP session with the router's web interface."""

    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url

    @classmethod
    def connect(cls, ip):
        """Open a session to the router, trying HTTP first and then HTTPS.

        Returns None if the router is unreachable over both.
        """
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
                session.get(f"{base_url}/Main_Login.asp", timeout=REQUEST_TIMEOUT)
                return cls(session, base_url)
            except requests.exceptions.RequestException:
                session.close()
        return None

    def get(self, path):
        """GET a page relative to the router's base URL."""
        return self.session.get(f"{self.base_url}/{path}", timeout=REQUEST_TIMEOUT)

    def post(self, path, **kwargs):
        """POST to a page relative to the router's base URL."""
        return self.session.post(f"{self.base_url}/{path}", timeout=REQUEST_TIMEOUT, **kwargs)

    def nvram_get(self, key):
        """Read one NVRAM variable. Requires a logged-in session."""
        # This firmware only returns the first key when multiple hooks are passed
        # to appGet.cgi, so request one key at a time
        return self.get(f"appGet.cgi?hook=nvram_get({key})").json().get(key, "").strip()

    def login_state(self):
        """Read the failed-login state embedded in the login page."""
        html = self.get("Main_Login.asp").text
        # e.g. { "lock_time": 194, "error_status": 10, "error_num": 2, ... }
        match = re.search(r"var login_info = tryParseJSON\('(.*?)'\);", html)
        login_info = json.loads(match.group(1)) if match else {}
        match = re.search(r"var captcha_enable = htmlEnDeCode\.htmlEncode\(decodeURIComponent\('(\d*)'\)\)", html)
        return LoginState(
            error_status=login_info.get("error_status", ""),
            error_num=login_info.get("error_num", 0),
            lock_time=login_info.get("lock_time", 0),
            last_time_lock_warning=bool(login_info.get("last_time_lock_warning")),
            captcha_enabled=match.group(1) != "0" if match else True,
        )

    def captcha_image(self):
        """Download the captcha image (GIF bytes) the next login has to answer."""
        return self.get("captcha.gif").content

    def login(self, username, password, captcha=""):
        """Log in and return True on success.

        Same flow as the web UI: get a one-time nonce, then send a salted SHA-256
        of the credentials instead of the password itself.
        """
        nonce_id = random_string(10)
        nonce = self.post("get_Nonce.cgi", json={"id": nonce_id}).json()["nonce"]
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
        self.post("login_v2.cgi", data=login_data).raise_for_status()
        # On success the router sets an asus_token cookie
        return bool(self.session.cookies.get("asus_token"))

    def firmware_version(self):
        """Read the installed firmware version."""
        return FirmwareVersion(
            firmver=self.nvram_get("firmver"),
            buildno=self.nvram_get("buildno"),
            extendno=self.nvram_get("extendno"),
        )

    def check_for_update(self):
        """Have the router check the ASUS servers and wait for the result.

        webs_state_update turns "1" once the check has finished (it does not mean
        an update exists). webs_state_flag is "1" (or "2" for a forced update)
        when a newer firmware is available, and webs_state_info holds the latest
        version string the web UI shows.
        """
        self.post("apply.cgi", data={
            "action_mode": "apply",
            "action_script": "start_webs_update",
            "action_wait": "0",
        })
        finished = False
        error = ""
        for _ in range(UPDATE_POLL_ATTEMPTS):
            time.sleep(UPDATE_POLL_INTERVAL)
            finished = self.nvram_get("webs_state_update") == "1"
            error = self.nvram_get("webs_state_error")
            if finished or error not in ("", "0"):
                break
        return UpdateCheckResult(
            finished=finished,
            error=error,
            update_available=self.nvram_get("webs_state_flag") in ("1", "2"),
            latest_version=self.nvram_get("webs_state_info"),
        )


def random_string(length):
    """Random alphanumeric string, like the web UI's randomString()."""
    alphabet = string.digits + string.ascii_letters
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ask_for_captcha(router):
    """Show the router's captcha image and return the text the user types.

    Guessing the captcha automatically is not worth it: every wrong answer
    counts as a failed login, and after 10 the router locks the web UI until a
    factory reset.
    """
    with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as f:
        f.write(router.captcha_image())
    captcha_path = Path(f.name)
    try:
        print("The router requires a captcha because of previous failed logins.")
        print(f"Captcha image: {captcha_path}")
        webbrowser.open(captcha_path.as_uri())
        return input("Captcha text: ").strip()
    finally:
        os.remove(captcha_path)


def describe_login_failure(state):
    """Explain a failed or blocked login based on the router's login state."""
    if state.error_status == ERROR_INVALID_CREDENTIALS:
        message = "Login failed - invalid username or password."
    elif state.error_status == ERROR_TEMPORARILY_LOCKED:
        message = f"Login is locked after 5 failed attempts. Try again in {state.lock_time} seconds."
    elif state.error_status == ERROR_WRONG_CAPTCHA:
        message = "Login failed - the captcha was wrong."
    elif state.error_status == ERROR_PERMANENTLY_LOCKED:
        message = ("The router locked its web login after 10 failed attempts. "
                   "It has to be reset to factory settings to unlock it.")
    else:
        message = f"Login failed (router error status {state.error_status!r})."
    if state.last_time_lock_warning and state.error_status != ERROR_PERMANENTLY_LOCKED:
        message += ("\nWarning: one more failed attempt will lock the router until "
                    "it is reset to factory settings.")
    return message


def log_in(router, username, password):
    """Log in, asking for a captcha if needed. Prints the reason and returns False on failure.

    Does not even try while the router is locked out, since every attempt counts
    toward the permanent lockout.
    """
    state = router.login_state()
    if state.is_locked:
        print(describe_login_failure(state))
        return False
    captcha = ask_for_captcha(router) if state.needs_captcha else ""
    if router.login(username, password, captcha):
        return True
    print(describe_login_failure(router.login_state()))
    return False


def describe_update_result(result, current):
    """Explain the outcome of an update check to the user."""
    if result.failed:
        return f"The router failed to reach the ASUS update servers (error code {result.error})."
    if not result.finished:
        return "Timed out waiting for the router to finish checking for updates."
    if result.update_available:
        return (f"A new firmware update is available: {current.format_latest(result.latest_version)}\n"
                f"Current version: {current}")
    return "No firmware update currently available. The system is up to date."


def check_asus_firmware_update(ip, username, password):
    """Log in to the router at `ip` and report whether a firmware update is available."""
    router = Router.connect(ip)
    if not router:
        print(f"Could not connect to the router at {ip} (tried both HTTP and HTTPS).")
        return

    try:
        if not log_in(router, username, password):
            return

        current = router.firmware_version()
        print(f"Current version: {current}")

        print("Checking against ASUS servers...")
        result = router.check_for_update()

        print()
        print(describe_update_result(result, current))
        # Here you can add code to send a notification (e.g., via a Telegram Bot or SMTP email)
        # when result.update_available is True
    except requests.exceptions.RequestException as e:
        print(f"Communication error with the router: {e}")


if __name__ == "__main__":
    ROUTER_IP = input("Router IP (Enter for '192.168.50.1'): ").strip() or "192.168.50.1"
    USERNAME = input("Username (Enter for 'admin'): ").strip() or "admin"
    PASSWORD = getpass.getpass("Password: ")

    check_asus_firmware_update(ROUTER_IP, USERNAME, PASSWORD)
