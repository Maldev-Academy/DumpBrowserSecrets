## DumpBrowserSecrets

Extracts browser-stored data such as refresh tokens, cookies, saved credentials, credit cards, autofill entries, browsing history, and bookmarks from modern Chromium-based and Gecko-based browsers (Chrome, Microsoft Edge, Firefox, Opera, Opera GX, and Vivaldi).

<br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)

[Maldev Database](https://search.maldevacademy.com?ref=gh)
  
[Malware Development Course Syllabus](https://maldevacademy.com/maldev-course/syllabus?ref=gh)

[Offensive Phishing Operations Course Syllabus](https://maldevacademy.com/phishing-course/syllabus?ref=gh)

[Ransomware Internals, Simulation and Detection Course Syllabus](https://maldevacademy.com/ransomware-course/syllabus?ref=gh)

<br>

## How Does It Work

This project is an improved version of [DumpChromeSecrets](https://github.com/Maldev-Academy/DumpChromeSecrets), and similarly consists of two components:

1. **Executable (`DumpBrowserSecrets.exe`)**

  Creates a headless Chromium process, injects the DLL via [Early Bird APC injection](https://attack.mitre.org/techniques/T1055/004/), and receives extracted decryption keys. These keys are either App-Bound (extracted from Chrome, Brave, and Microsoft Edge) or DPAPI keys (used by Opera, Opera GX, and Vivaldi). Once the required keys have been recovered, this executable parses the browser's SQLite databases and JSON files on disk and decrypts the stored data, including credentials, cookies, tokens, and other browsing data. 
  Additionally, when targeting non-Chromium-based browsers (e.g., Firefox), `DumpBrowserSecrets.exe` handles all the required steps for data extraction and decryption (without DLL-Injection).

<br>


2. **DLL (`DllExtractChromiumSecrets.dll`)**

  Runs inside Chromium browsers to decrypt the App-Bound encryption key using the `IElevator` COM interface. It leverages the `IElevator` COM interface to decrypt the App-Bound encryption key and retrieves the decrypted values of `app_bound_encrypted_key` and `encrypted_key` from the targeted browser's `Local State` file. These values are then returned to the executable, which performs all extraction operations.

<br>

> [!NOTE]
> Unlike the [DumpChromeSecrets](https://github.com/Maldev-Academy/DumpChromeSecrets) project, this implementation performs all browser data extraction in the `DumpBrowserSecrets.exe` executable, while the DLL is limited to retrieving encryption keys from Chromium-based browsers.


<br>

### Usage

```
Usage: DumpBrowserSecrets.exe [options]

Options:
  /b:<browser> Target Browser: Chrome, Edge, Brave, Opera, Operagx, Vivaldi, Firefox, All
               (Default: System Default Browser)
  /o <file>    Output JSON File (Default: <Browser>Data.json)
  /spoof       Enable Argument and PPID Spoofing When Retrieving ABE Keys From Chromium-Based Browsers
  /all         Export All Entries (Default: Max 16 per Category)
  /?           Show This Help Message

Examples:
  DumpBrowserSecrets.exe                            Extract 16 Entries From The Default Browser
  DumpBrowserSecrets.exe /b:chrome /spoof           Extract 16 Entries From Chrome With PPID and Argument Spoofing
  DumpBrowserSecrets.exe /b:firefox /all            Export All Entries From Firefox
  DumpBrowserSecrets.exe /b:brave /o Output.json    Extract 16 Entries From Brave To Output.json
  DumpBrowserSecrets.exe /b:all /all                Extract All From All Installed Browsers

```

<br>

## Extracted Data

The tables below showcase the exact data locations, formats, and encryption models used by each supported browser.

<br>

### Chrome (App-Bound)

| Data Type    | Database Path                                                      | Format | Encryption        |
|--------------|--------------------------------------------------------------------|--------|-------------------|
| Cookies      | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies`   | SQLite | V20               |
| Logins       | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`        | SQLite | V20               |
| Credit Cards | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data`          | SQLite | V20               |
| Tokens       | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data`          | SQLite | V20               |
| Autofill     | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data`          | SQLite | Unencrypted       |
| History      | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History`           | SQLite | Unencrypted       |
| Bookmarks    | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks`         | JSON   | Unencrypted       |

### Edge (App-Bound)

| Data Type    | Database Path                                                      | Format | Encryption        |
|--------------|--------------------------------------------------------------------|--------|-------------------|
| Cookies      | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies`  | SQLite | V20               |
| Logins       | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`       | SQLite | V20               |
| Credit Cards | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data`         | SQLite | V20               |
| Tokens       | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data`         | SQLite | X                 |
| Autofill     | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data`         | SQLite | Unencrypted       |
| History      | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History`          | SQLite | Unencrypted       |
| Bookmarks    | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks`        | JSON   | Unencrypted       |

### Brave (App-Bound)

| Data Type    | Database Path                                                                     | Format | Encryption        |
|--------------|-----------------------------------------------------------------------------------|--------|-------------------|
| Cookies      | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies`    | SQLite | V20               |
| Logins       | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data`         | SQLite | V20               |
| Credit Cards | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Web Data`           | SQLite | V20               |
| Tokens       | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Web Data`           | SQLite | X                 |
| Autofill     | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Web Data`           | SQLite | Unencrypted       |
| History      | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History`            | SQLite | Unencrypted       |
| Bookmarks    | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks`          | JSON   | Unencrypted       |

### Opera (DPAPI)

| Data Type    | Database Path                                                        | Format | Encryption   |
|--------------|----------------------------------------------------------------------|--------|--------------|
| Cookies      | `%APPDATA%\Opera Software\Opera Stable\Default\Network\Cookies`      | SQLite | V10          |
| Logins       | `%APPDATA%\Opera Software\Opera Stable\Default\Login Data`           | SQLite | V10          |
| Credit Cards | `%APPDATA%\Opera Software\Opera Stable\Default\Web Data`             | SQLite | V10          |
| Tokens       | `%APPDATA%\Opera Software\Opera Stable\Default\Web Data`             | SQLite | V10 + Base64 |
| Autofill     | `%APPDATA%\Opera Software\Opera Stable\Default\Web Data`             | SQLite | Unencrypted  |
| History      | `%APPDATA%\Opera Software\Opera Stable\Default\History`              | SQLite | Unencrypted  |
| Bookmarks    | `%APPDATA%\Opera Software\Opera Stable\Default\Bookmarks`            | JSON   | Unencrypted  |

### Opera GX (DPAPI)

| Data Type    | Database Path                                                        | Format | Encryption   |
|--------------|----------------------------------------------------------------------|--------|--------------|
| Cookies      | `%APPDATA%\Opera Software\Opera GX Stable\Default\Network\Cookies`   | SQLite | V10          |
| Logins       | `%APPDATA%\Opera Software\Opera GX Stable\Default\Login Data`        | SQLite | V10          |
| Credit Cards | `%APPDATA%\Opera Software\Opera GX Stable\Default\Web Data`          | SQLite | V10          |
| Tokens       | `%APPDATA%\Opera Software\Opera GX Stable\Default\Web Data`          | SQLite | V10 + Base64 |
| Autofill     | `%APPDATA%\Opera Software\Opera GX Stable\Default\Web Data`          | SQLite | Unencrypted  |
| History      | `%APPDATA%\Opera Software\Opera GX Stable\Default\History`           | SQLite | Unencrypted  |
| Bookmarks    | `%APPDATA%\Opera Software\Opera GX Stable\Default\Bookmarks`         | JSON   | Unencrypted  |


### Vivaldi (DPAPI)

| Data Type    | Database Path                                                | Format | Encryption   |
|--------------|--------------------------------------------------------------|--------|--------------|
| Cookies      | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Network\Cookies`   | SQLite | V10          |
| Logins       | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Login Data`        | SQLite | V10          |
| Credit Cards | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Web Data`          | SQLite | V10          |
| Tokens       | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Web Data`          | SQLite | X            |
| Autofill     | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Web Data`          | SQLite | Unencrypted  |
| History      | `%LOCALAPPDATA%\Vivaldi\User Data\Default\History`           | SQLite | Unencrypted  |
| Bookmarks    | `%LOCALAPPDATA%\Vivaldi\User Data\Default\Bookmarks`         | JSON   | Unencrypted  |

### Firefox (NSS)

| Data Type    | File / Database Path                                                | Format    | Encryption               |
|--------------|---------------------------------------------------------------------|-----------|--------------------------|
| Cookies      | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\cookies.sqlite`       | SQLite    | Unencrypted              |
| Logins       | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json`          | JSON      | AES‑256‑CBC or 3DES‑CBC  |
| Tokens       | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\signedInUser.json`    | JSON      | Unencrypted              |
| Autofill     | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\formhistory.sqlite`   | SQLite    | Unencrypted              |
| History      | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite`        | SQLite    | Unencrypted              |
| Bookmarks    | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite`        | SQLite    | Unencrypted              |



<br>


## Credits

* **Chromme IElevator COM interface research from [snovvcrash's gist](https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824)**
* **Edge & Brave IElevator COM interface research from [Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)**
* **[luci4](https://github.com/l00sy4) for technical guidance**
* **SQLite amalgamation from [sqlite.org](https://www.sqlite.org/amalgamation.html)**

<br>

## Demo

https://github.com/user-attachments/assets/4290d525-7d5f-4a65-8624-2f9fa752e186




