
# Mediroza General Hospital — Penetration Testing Report

**Client:** Mediroza General Hospital | **Target:** https://medirozahospital.com | **Engagement type:** Black-box Penetration Test | **Date:** Nov 25, 2026 | **Tester:**  Jugin Zenzele Ngobese (Networkwalks, Batch B084)

## Executive Summary

This engagement identified a **Critical**-risk SQL injection vulnerability in the Mediroza patient portal login form, which allowed authentication bypass without valid credentials. Chained with a predictable, disclosed directory structure (`robots.txt` plus unprotected directory listings), this access led to the retrieval of three password-protected patient pathology reports, all of which were successfully decrypted. A further exposure — an unauthenticated, publicly indexed `/old/` directory — contained a full 2019 MySQL database backup disclosing the salary and national ID details of all 30 hospital staff, as well as the hospital's confidential shareholder register.

Overall, the assessment found the application to have no working Web Application Firewall, a vulnerable and unpatched Joomla-era codebase, verbose SQL error disclosure, and multiple instances of sensitive data (patient records, payroll, and ownership information) left reachable to any unauthenticated internet user. These findings represent a severe breach of patient confidentiality (relevant to POPIA compliance in South Africa) and expose the hospital to significant reputational, legal and financial risk.

**Overall Risk Rating: Critical**

## Scope and Methodology

**Target:** `medirozahospital.com` (patient portal, staff portal, and supporting infrastructure).

**Approach:** Full black-box test, limited to the target domain. No social engineering and no denial-of-service testing was performed, per the rules of engagement. Written authorisation for all testing was granted by the client.

**Tools used:**

| Tool | Purpose |
| --- | --- |
| `whois` | Domain registration and registrar information |
| `whatweb` | Web technology fingerprinting |
| `nslookup` | DNS resolution |
| `curl` | HTTP header inspection |
| `wafw00f` | Web Application Firewall detection |
| `dnsrecon` | DNS enumeration |
| OWASP JoomScan | Joomla-specific vulnerability scanning |
| `gobuster` | Directory and file brute-forcing |
| Burp Suite Community Edition | Intercepting proxy, manual request tampering |
| Firefox | Manual browsing and directory-listing review |
| Networkwalks Hash Calculator | Browser-based extraction of pdf2john/hashcat-compatible hashes from encrypted PDFs |
| Networkwalks Password Cracker | Browser-based dictionary attack against extracted PDF hashes |

**Methodology:** The engagement followed a standard black-box methodology: passive and active reconnaissance, technology fingerprinting, attack surface mapping (directory brute-forcing and robots.txt review), vulnerability identification, exploitation to demonstrate real-world impact, and evidence-based reporting.

**Limitations encountered:** `dnsrecon` general enumeration failed with a DNS timeout; this did not materially affect the assessment, as the required attack surface was already identified through other means (robots.txt, gobuster, and JoomScan).

## Findings — M1: Initial Access

**Risk Rating: Critical**

### 1.1 Reconnaissance

Initial reconnaissance was carried out using `whois`, `whatweb`, `nslookup`, `curl`, `wafw00f` and `dnsrecon` against `medirozahospital.com`.

- `whois` showed the domain is registered through NameCheap, created 2026-08-14, with no DNSSEC signing.
- `whatweb` identified the server as LiteSpeed, hosted in the United States at IP `199.188.201.16`, redirecting HTTP to HTTPS.
- `nslookup` confirmed the A record resolving to `199.188.201.16`.
- `curl -I` returned HTTP/2 200 with a `Last-Modified` header of 4 September 2026, indicating a static or infrequently-updated codebase, and disclosed the `x-turbo-charged-by: LiteSpeed` header.
- `wafw00f` detected a LiteSpeed WAF signature; however, OWASP JoomScan separately reported no active firewall blocking its requests, suggesting the WAF (if present) was not meaningfully filtering malicious traffic.
- `dnsrecon -d` failed with a DNS timeout error during general enumeration and did not return useful results.



*Figure 1.1a — WHOIS record for the target domain.*



*Figure 1.1b — Technology fingerprint via whatweb.*



*Figure 1.1c — DNS resolution via nslookup.*


*Figure 1.1d — HTTP response headers via curl.*



*Figure 1.1e — WAF fingerprint via wafw00f.*


*Figure 1.1f — dnsrecon timeout (enumeration inconclusive).*

### 1.2 Attack Surface Mapping

OWASP JoomScan identified the application as running **Joomla 1.4.2**, an end-of-life CMS version with numerous known vulnerabilities. No active firewall blocked the scan. Critically, JoomScan's `robots.txt` check disclosed three unlisted, non-linked paths:

```
https://medirozahospital.com/patient/
https://medirozahospital.com/staff/
https://medirozahospital.com/old/
```

A follow-up `gobuster` directory brute-force against the webroot confirmed a large number of `/~username/` paths returning HTTP 301 redirects, alongside standard sensitive paths (`.git/HEAD`, `.htpasswd`, `.htaccess`, `.svn`) blocked with 403 Forbidden — indicating the web server itself was reasonably hardened, but the application layer (robots.txt disclosure and unprotected directory indexes, see §1.4) was not.

## Findings — M2: Data Extraction (Encryption Cracking)

**Risk Rating: High**

The three pathology PDFs retrieved in §1.4 were distributed as “password-protected” documents via the Patient Portal (owner/user-password PDF encryption). Each file's encryption was cracked and the full contents recovered:

| File | Patient | Lab Ref | Date |
| --- | --- | --- | --- |
| patient\_report\_1.pdf | Sipho Dlamini | LR-2024-1187 | 2024-11-04 |
| patient\_report\_2.pdf | Priya Reddy | LR-2024-1192 | 2024-11-05 |
| patient\_report\_3.pdf | Emily Thompson | LR-2024-1205 | 2024-11-06 |

Each report discloses the patient's full name, date of birth, hospital patient ID, referring doctor, specimen type, lab reference number, and a full pathology results table (haemoglobin, white cell count, cholesterol panel, glucose, creatinine, ferritin, TSH, vitamin D, etc., each flagged Normal/High/Low against clinical reference ranges) — confirming that patient-identifiable health data (PHI) was fully recoverable by an unauthenticated external attacker.



*Figure 2a — Decrypted patient\_report\_1.pdf (S. Dlamini).*



*Figure 2b — Decrypted patient\_report\_2.pdf (P. Reddy).*



*Figure 2c — Decrypted patient\_report\_3.pdf (E. Thompson).*

### 2.1 Methodology: Hash Extraction and Dictionary Attack

Each encrypted PDF was processed using two Networkwalks Academy browser-based tools:

1. **Hash Calculator** (`networkwalks.com/hash-calculator`) — the PDF is parsed client-side (no upload to a server) and, where it detects owner/user-password encryption, extracts a crackable hash in `pdf2john`/hashcat-compatible format (`$pdf$...`), along with the PDF's revision, version and key length (R3, V2, 128-bit RC4 for all three files).
2. **Password Cracker** (`networkwalks.com/password-cracker`) — a dictionary-attack simulator that hashes each word in a wordlist (MD5 + RC4 key derivation, mirroring the approach used by tools such as John the Ripper) and compares it against the extracted PDF hash until a match is found.

**Results:**

| File | Hash tool output | Wordlist position | Recovered password |
| --- | --- | --- | --- |
| patient\_report\_1.pdf | `$pdf$2*3*128*...` (R3/128-bit) | 1 / 100 | `123456` |
| patient\_report\_2.pdf | `$pdf$2*3*128*...` (R3/128-bit) | 2 / 100 | `password` |
| patient\_report\_3.pdf | `$pdf$2*3*128*...` (R3/128-bit) | 3546 / 3556 | `!@#$%^&` |

All three passwords were weak and either trivially guessable (`123456`, `password`) or, in the third case, present in an extended symbol-based wordlist. This confirms the hospital's PDF report-encryption scheme relies on weak, predictable passwords rather than strong, randomly generated per-document secrets.


*Figure 2.1a — Hash extracted from patient\_report\_1.pdf (R3/128-bit).*



*Figure 2.1b — Password cracked for patient\_report\_1.pdf: `123456` (1/100 attempts).*



*Figure 2.1c — Hash extracted from patient\_report\_2.pdf (R3/128-bit).*



*Figure 2.1d — Password cracked for patient\_report\_2.pdf: `password` (2/100 attempts).*



*Figure 2.1e — Hash extracted from patient\_report\_3.pdf (R3/128-bit).*



*Figure 2.1f — Password cracked for patient\_report\_3.pdf: `!@#$%^&` (3546/3556 attempts).*

## Findings — M3: Critical Data Exposure (Legacy Database Backup)

**Risk Rating: Critical**

The `/old/` directory listing identified in §1.4 exposed `mediroza_db_backup_2019.sql`, a complete, unauthenticated, downloadable MySQL dump of the hospital's internal database. Analysis of this file revealed two tables of highly sensitive internal data that go well beyond the patient data targeted in M1/M2:

### 3.1 Staff Table — Salaries and National IDs

The `staff` table contains 30 records, one per hospital employee, with columns `full_name`, `job_title`, `department`, `email`, `phone`, **`national_id`**, **`monthly_salary_zar`**, and `date_joined`. This discloses the complete payroll of the hospital and the South African national identity numbers of every staff member — from the Medical Director (Dr. Johan van der Merwe, R160,000/month) and Chief Financial Officer (Sarah Botha, R152,000/month) down to administrative and support staff (e.g. a Receptionist on R19,000/month).

### 3.2 Shareholders Table — Ownership Structure

The `shareholders` table discloses the hospital's confidential ownership register: 10 shareholders with `shareholder_name`, `share_percent`, `shares_held`, and `share_class`. Largest holders include Dr. Rajesh Naidoo (18%), Cedar Health Holdings (Pty) Ltd (15%), Dr. Johan van der Merwe (12%), and the Reddy Family Trust (11%), with several individual clinicians and staff members (including Dr. Ahmed Kara and Dr. Vikram Chetty) holding Preferential-class shares.

This exposure constitutes a severe breach of both employee privacy (national IDs, salaries) and corporate confidentiality (ownership structure), independent of and in addition to the patient-data breach covered in M1/M2.



*Figure 3a — Staff table from the exposed 2019 database backup, showing national IDs and salaries.*



*Figure 3b — Shareholders table from the exposed 2019 database backup.*

## Risk Rating

| # | Finding | Rating | Justification |
| --- | --- | --- | --- |
| 1 | SQL injection / authentication bypass on Patient Portal login | **Critical** | Unauthenticated remote attacker can bypass login entirely and access any patient's protected data; trivially exploitable with no prior access. |
| 2 | Verbose SQL error disclosure | **Medium** | Leaks database/application internals aiding further attacks; not independently exploitable for data access. |
| 3 | Unprotected directory listings (`/patient/`, `/staff/`, `/old/`) | **High** | Directly exposes application source paths, a readable error log, and a legacy database backup to any internet user. |
| 4 | `robots.txt` disclosure of sensitive, unlinked paths | **Low** | Does not itself grant access, but materially aids attackers in locating the above directories. |
| 5 | Encrypted patient PDF reports with crackable passwords | **High** | Confidential health records (PHI) protected only by weak/guessable passwords, fully recoverable offline. |
| 6 | Legacy database backup publicly exposed (`mediroza_db_backup_2019.sql`) | **Critical** | Discloses full staff payroll, national ID numbers, and the hospital's confidential shareholder/ownership register — a severe breach of employee privacy and corporate confidentiality. |
| 7 | Outdated, unpatched Joomla 1.4.2 CMS | **High** | End-of-life software with known public vulnerabilities; increases overall attack surface. |
| 8 | Ineffective WAF | **Medium** | WAF signature detected but did not block scanning or exploitation tooling during testing. |

**Overall engagement risk: Critical** — driven by findings 1 and 6, either of which alone would constitute a reportable data breach involving patient health information and/or employee personal information under South Africa's Protection of Personal Information Act (POPIA).

## Recommendations and Remediation

| Finding | Recommendation |
| --- | --- |
| SQL injection / auth bypass | Rewrite all database queries to use parameterised statements / prepared statements (e.g. PDO with bound parameters). Never concatenate user input directly into SQL. Add server-side input validation on all login fields. |
| Verbose SQL error disclosure | Disable `display_errors` in production PHP configuration; log errors server-side only and show generic error messages to users. |
| Unprotected directory listings | Disable directory indexing (`Options -Indexes` in Apache, or the LiteSpeed equivalent) across the webroot, and ensure every directory has either an `index` file or an explicit deny rule. |
| `robots.txt` disclosure | Remove sensitive, unlinked paths from `robots.txt`; rely on proper authentication and server-side access control rather than obscurity for any path that must stay reachable. |
| Weak PDF encryption on patient reports | Replace user-guessable PDF passwords with strong, randomly generated per-document passwords delivered through a secure, authenticated channel (not displayed in a public listing), or move to an authenticated in-portal viewer rather than downloadable encrypted files. |
| Exposed legacy database backup | Immediately remove `mediroza_db_backup_2019.sql` (and any other backup files) from all web-accessible directories. Store backups outside the webroot, encrypted at rest, with access restricted to authorised administrators only. Rotate all exposed credentials, national ID-linked accounts, and review for any downstream fraud risk. |
| Outdated Joomla 1.4.2 | Upgrade to a current, supported Joomla release (or migrate to a actively maintained CMS/custom application) and apply a documented patch-management schedule. |
| Ineffective WAF | Review and reconfigure the WAF rule set to ensure it actively blocks SQL injection, directory traversal, and automated scanning tooling; validate with periodic re-testing. |
| General | Conduct a full data-protection impact assessment under POPIA given the confirmed exposure of patient health information, staff national IDs/salaries, and shareholder data; notify the Information Regulator and affected data subjects as required. Implement a recurring (at minimum annual) penetration test and a responsible vulnerability-disclosure process. |



*Figure 1.2a — JoomScan version detection and robots.txt disclosure.*



*Figure 1.2b — gobuster directory enumeration.*

### 1.3 SQL Injection — Patient Portal Login (Critical)

The Patient Portal login form (`/patient/login.php`) was tested for injection by submitting a single apostrophe in the username field. The application returned a raw MySQL error:

> *Warning: mysqli\_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1*

This confirmed that user input was being concatenated directly into a SQL query with no sanitisation or use of prepared statements, and that detailed database errors were being returned to an unauthenticated user — both of which are serious weaknesses in their own right (verbose error disclosure aids further exploitation).

Using Burp Suite to intercept and tamper with the login POST request, the username field was set to `admin' --` style/classic authentication-bypass payloads (captured as `username=admin%27&password=test1` in the proxied request). This successfully bypassed the login mechanism and returned a valid, authenticated session (`PHPSESSID` cookie set), without knowledge of any valid credentials.


*Figure 1.3a — Verbose SQL error on the login form, confirming injectable input.*



*Figure 1.3b — Intercepted authentication-bypass request in Burp Suite.*

### 1.4 Unprotected Directory Listings and Patient Portal Access (Critical)

The three paths disclosed via `robots.txt` (§1.2) were browsed directly. All three returned fully indexable directory listings with no access control:

- **`/patient/`** — exposed `login.php`, `logout.php`, `portal.php`, `download.php`, and a readable `error_log` (250 KB), alongside a `reports/` folder.
- **`/staff/`** — exposed a separate `login.php` for hospital staff.
- **`/old/`** — exposed a single file, `mediroza_db_backup_2019.sql` (7 KB), a legacy full database backup (analysed further in §3 — Finding M3).

Using the SQL-injection authentication bypass described in §1.3 against `/patient/login.php`, an authenticated session was established on the Patient Portal without valid credentials. The resulting “My lab reports” page listed three password-protected PDF pathology reports available for download:

| Report | Lab Ref | Date |
| --- | --- | --- |
| Pathology Report — S. Dlamini | LR-2024-1187 | 2024-11-04 |
| Pathology Report — P. Reddy | LR-2024-1192 | 2024-11-05 |
| Pathology Report — E. Thompson | LR-2024-1205 | 2024-11-06 |

All three PDFs were downloaded, satisfying the Milestone 1 deliverable. Decryption of these files is covered under Finding M2 (§2).



*Figure 1.4a — Index of /patient/.*



*Figure 1.4b — Index of /staff/.*



*Figure 1.4c — Index of /old/, exposing the legacy database backup.*



*Figure 1.4d — Patient Portal accessed via SQL-injection auth bypass, showing all three target reports.*

## Learning Outcomes

This engagement, completed as part of Networkwalks Academy Batch B084, developed and demonstrated the following practical skills:

- **Reconnaissance and fingerprinting** — using `whois`, `nslookup`, `whatweb`, `curl` and `wafw00f` to profile a target's infrastructure, hosting, and defensive posture before any active testing.
- **Attack surface mapping** — using OWASP JoomScan and `gobuster` to enumerate CMS versions, hidden paths, and brute-forceable directories, and recognising how a routine file like `robots.txt` can itself leak sensitive paths.
- **Web application exploitation** — identifying and manually exploiting a SQL injection vulnerability to achieve authentication bypass, including interpreting verbose database error messages as a diagnostic signal and using Burp Suite to intercept and tamper with HTTP requests.
- **Recognising information-disclosure vulnerabilities** — understanding how unprotected directory listings, verbose errors, and legacy files left on a production server can be as damaging as a direct exploit, even without any "hacking" in the traditional sense.
- **Offline/dictionary password attacks** — extracting crackable hashes from encrypted PDFs and running dictionary attacks to recover weak passwords, and understanding why password strength and key-derivation choices matter for document protection.
- **Data-exposure analysis** — analysing a recovered database backup to identify categories of sensitive data (PII, payroll, ownership records) beyond the originally targeted patient reports, and distinguishing data of different sensitivity levels and legal implications (e.g. POPIA-relevant data).
- **Professional reporting** — translating technical findings into a structured, evidence-backed report with risk ratings and actionable remediation guidance suitable for a non-technical client audience, including using AI tooling responsibly to assist with drafting and organisation while retaining ownership of the technical work.

Together, these outcomes cover the full penetration-testing lifecycle: reconnaissance, enumeration, exploitation, post-exploitation data analysis, and client-facing reporting.

## Note on AI Assistance

As permitted and encouraged under the engagement brief (Milestone 3), Claude (Anthropic's AI assistant) was used to assist with report compilation: structuring findings, drafting narrative explanations of each vulnerability, formatting evidence tables, and embedding the tester's own screenshots as supporting figures. All reconnaissance, exploitation, decryption, and data analysis described in this report were performed directly by the tester using the tools listed in §2 (Burp Suite, gobuster, JoomScan, Networkwalks Hash Calculator/Password Cracker, etc.); Claude did not independently access the target or any of its data.

👤 Author

**Jugin Zenzele Ngobese**

Cybersecurity & Ethical Hacking Intern at Networkwalks B084

LinkedIn: \[<https://www.linkedin.com/in/zenzele-ngobese-2b5316419/>)
