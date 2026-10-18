import requests
import base64
import time
import getpass

def nvram_get(session, base_url, key):
    # This firmware only returns the first key when multiple hooks are passed
    # to appGet.cgi, so request one key at a time
    resp = session.get(f"{base_url}/appGet.cgi?hook=nvram_get({key})", timeout=10)
    return resp.json().get(key, "")

def check_asus_firmware_update(ip, username, password):
    session = requests.Session()

    # ASUS routers usually use plain HTTP on the internal network
    # If you configured HTTPS for the admin interface, change to https://
    base_url = f"http://{ip}"

    # Encode the username and password in Base64 as required by the ASUS API
    auth_string = f"{username}:{password}"
    encoded_auth = base64.b64encode(auth_string.encode()).decode()

    login_data = {
        "login_authorization": encoded_auth,
        "action_mode": "",
        "action_script": "",
        "action_wait": "5",
        "current_page": "Main_Login.asp",
        "next_page": "index.asp"
    }

    try:
        # Step 1: Log in to the router and save the cookies.
        # The router refuses login.cgi unless the login page was requested
        # first with a matching Referer; on success it sets an asus_token cookie
        session.headers.update({"Referer": f"{base_url}/Main_Login.asp"})
        session.get(f"{base_url}/Main_Login.asp", timeout=10)
        login_response = session.post(f"{base_url}/login.cgi", data=login_data, timeout=10)
        login_response.raise_for_status()

        if not session.cookies.get("asus_token"):
            print("Login failed - check the username and password.")
            return

        # Current version details, e.g. 3.0.0.6.102_40284-g167db18_1581-gca342_BB0B
        firmver = nvram_get(session, base_url, "firmver")
        buildno = nvram_get(session, base_url, "buildno")
        extendno = nvram_get(session, base_url, "extendno")
        current_version = f"{firmver}.{buildno}_{extendno}".strip("._")
        current_build = f"{buildno}_{extendno.split('-')[0]}" if extendno else buildno
        print(f"Current version: {current_version}")

        # Step 2: Send a command to start the update check against ASUS servers
        check_data = {
            "action_mode": "apply",
            "action_script": "start_webs_update",
            "action_wait": "0"
        }
        session.post(f"{base_url}/apply.cgi", data=check_data, timeout=10)

        # Step 3: Poll for the result. webs_state_info holds the latest version
        # string (the same value the web UI shows as "The latest version"),
        # webs_state_update is "1" when an update is available
        print("Checking against ASUS servers...")
        latest_version = ""
        update_flag = ""
        error = ""
        for _ in range(5):
            time.sleep(5)
            latest_version = nvram_get(session, base_url, "webs_state_info").strip()
            update_flag = nvram_get(session, base_url, "webs_state_update").strip()
            error = nvram_get(session, base_url, "webs_state_error").strip()
            if latest_version or update_flag == "1" or (error and error != "0"):
                break

        # webs_state_info looks like "3006_102_40338-g47bdafb_1586-g1f414":
        # strip the leading firmware digits to get the build number ("102_40338"),
        # then rebuild the dotted display format the web UI uses
        latest_build = ""
        latest_display = latest_version
        if latest_version:
            head, _, suffix = latest_version.partition("-")
            firm_digits = firmver.replace(".", "")
            latest_build = head[len(firm_digits) + 1:] if head.startswith(firm_digits + "_") else head
            latest_display = f"{firmver}.{latest_build}-{suffix}" if suffix else latest_version

        print()
        if error and error != "0":
            print(f"The router failed to reach the ASUS update servers (error code {error}).")
        elif update_flag == "1" or (latest_build and current_build and latest_build != current_build):
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
