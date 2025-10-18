# XSS-Scanner 

A versatile Python script for discovering and demonstrating Cross-Site Scripting (XSS) vulnerabilities. This tool provides an interactive interface to test for Reflected, Stored, and DOM-based XSS, and includes a module for simulating session hijacking attacks.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Using this script on websites without explicit permission is illegal. The author is not responsible for any misuse or damage caused by this program.

## Features

#### Interactive CLI: A simple command-line menu to guide you through the scanning process.

#### Multiple XSS Vectors:

- Server-Side (Reflected/Stored): Tests GET and POST parameters using a classic payload list. Can distinguish between Reflected and potential Stored XSS.

- Client-Side (DOM-based): Uses Selenium and a real browser to test URL fragments (#) for vulnerabilities in client-side JavaScript.

#### Session Hijacking Simulation: A dedicated module to demonstrate the impact of XSS. It generates malicious links, serves a payload via a local PHP server, and can capture session data.

#### Flexible Parameter Testing: Can test a single parameter in isolation or test one vulnerable parameter in the context of others.

#### JSON Output: Saves discovered vulnerabilities to an XSS_vuln_params.json file for easy review.

# Installation

## 1. Prerequisites

Python 3.6+

PHP: Required for the Session Hijacking module to run the local web server.

Firefox and GeckoDriver: Required for the DOM-based scanner. The script attempts to install GeckoDriver automatically via webdriver-manager.

## 2. Setup

Clone the repository:

    git clone https://github.com/Xenobie/XSS-Scanner.git
    cd XSS-Scanner

(Recommended) Create a virtual environment:

    python3 -m venv venv
    source venv/bin/activate

Install Python libraries:
Bash

    pip install -r requirements.txt

If requirements.txt is missing, install them manually:
Bash

    pip install requests selenium webdriver-manager

# 3. Usage

Run the script from your terminal:

    python3 xssscan.py

Follow the interactive prompts to select a mode and provide the necessary information (URL, parameters, etc.).

### Modes of Operation

- #### Server POST test (Stored XSS):
Sends POST requests with payloads to an injection URL.
Checks the response page and a separate "view" page to determine if the payload was stored.

- #### Server GET test (Isolated):
Tests each GET parameter individually (page.php?param=PAYLOAD).
Useful for simple forms and quick checks.

- #### Server GET test (Multiple Params):
Tests one parameter at a time while keeping others populated with test data (page.php?vuln_param=PAYLOAD&other_param=test).
Simulates a more realistic scenario of a complex form submission.

- #### DOM test (URL Fragment):

Launches a real Firefox browser using Selenium.

Injects payloads into the URL fragment (page.php#param=PAYLOAD) and waits for a JavaScript alert() to trigger.

- #### Session Hijacking:

This is a two-part module for demonstrating a full attack chain.


Setup: You must first create a script.js file in the same directory. This file contains the JavaScript payload that will steal cookies or perform other actions. Remember to configure the IP address inside script.js to point to your machine.

Execution: The script will ask for your IP and a port. It then generates a crafted link (for Reflected) or provides instructions (for Stored). When a victim clicks the link, their browser executes your script.js, which is served by a temporary PHP server started by the tool.

## TODO

Here are some potential improvements and features for the future:

    [ ] Payload Expansion: Integrate more comprehensive XSS payload lists from sources like the PortSwigger cheat sheet.

    [x] Authenticated Scanning: Add full session/cookie support to test pages that require login across all modules.

    [ ] Web Crawler: Implement a basic crawler to automatically discover links and potential parameters to test on a target domain.

    [ ] Headless Mode: Add an option to run the DOM scanner in a headless browser so it can run on servers without a GUI.

    [ ] Improved Reporting: Generate results in different formats like HTML or CSV for better readability.

    [ ] Multithreading: Speed up scans by testing multiple parameters or URLs concurrently.

    [ ] Custom Headers & User-Agent: Allow users to specify custom HTTP headers and a User-Agent for scanning.

    [ ] WAF Detection: Add basic checks to identify the presence of a Web Application Firewall (WAF) that might be blocking payloads.