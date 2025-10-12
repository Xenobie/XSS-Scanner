# XSS-Scanner
Manual (almost) xss-scannig script

# Features

Interactive Interface: Convenient command line menu for selecting the mode of operation.

Multi-mode scanning:
    
Server-Side (Reflected/Stored):
            - Testing a single parameter in isolation (page.php?param=PAYLOAD).
            - Testing one parameter in the presence of others (page.php?param1=PAYLOAD&param2=test).
            - Support for GET and POST requests.
            - Two-stage testing for Stored XSS (injection and verification).
Client-Side (DOM-based):
            - Special mode for testing parameters in URL fragment (page.php#param=PAYLOAD).
            - Using Selenium to emulate a real browser and execute JavaScript.
# Installation

Clone the repository (or just download the script):

    git clone https://github.com/Xenobie/XSS-Scanner.git
    cd XSS-Scanner

Install the required libraries using pip:

    pip install -r requirements.txt

(If the requirements.txt file does not exist, install them manually):

    pip install requests selenium webdriver-manager
Also wou will need Gecko Driver for selenium

    https://github.com/mozilla/geckodriver/releases

# Usage

Run the script from your terminal:

    python3 xssscan.py

Then follow the instructions in the interactive menu.

### Example 1: Search for Reflected XSS in multiple GET parameters

Select the "Server test (multiple GET parameters)" mode.

Enter the base URL: http://testphp.vulnweb.com/search.php

Enter parameter names: query, search, text

The script will test each parameter in turn with all available peyloads.

#### Example 2: Searching DOM XSS

Select the "DOM test (one parameter per URL fragment, #)" mode.

Enter the base URL: http://yourapp.com/vulnerable_page.html

Enter parameter name: param

The script will launch the browser, navigate to the page, and dynamically change the hash (#param=PAYLOAD) to test the client JavaScript response.

#### Example 3: Finding Stored XSS

To test Stored XSS with login, you will need to edit the if __name__ == "__main__:" section in the script:

just uncomment block of code and specify login url, username, password
