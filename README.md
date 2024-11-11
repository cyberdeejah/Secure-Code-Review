# Secure Code Review Tool

## Overview

The **Secure Code Review** tool is an automated code scanning solution designed to detect vulnerabilities in source code written in multiple programming languages. The tool supports over six popular programming languages, including Python, C++, Java, PHP, and others. It leverages static code analysis and metadata-driven techniques to provide detailed vulnerability reports that help developers and security professionals identify and fix security issues early in the development lifecycle.

The tool performs an in-depth scan of your codebase, identifies common vulnerabilities, and generates comprehensive reports, including recommendations, severity levels, and relevant CWE (Common Weakness Enumeration) IDs, as well as OWASP vulnerability categories.

### Key Features:

- **Multi-Language Support**: Scans code in **Python**, **C++**, **Java**, **PHP**, and other widely-used programming languages.
- **Metadata Integration**: Utilizes metadata to associate vulnerabilities with specific CWE IDs, OWASP top 10 categories, and severity levels.
- **Comprehensive Reports**: Generates detailed reports that include information on the found vulnerabilities, severity, CWE IDs, and practical recommendations for mitigation.
- **Code Line Identification**: Identifies the exact line of code where a vulnerability occurs, helping developers quickly pinpoint issues.
- **Log & Temporary Files**: Provides both temporary and log files of the scan results for audit and debugging purposes.
- **Dependency Scanning**: Incorporates aggressive dependency scanning techniques to identify vulnerabilities in external libraries and packages.
- **Automation Ready**: Built as a Bash script for easy automation, making it suitable for CI/CD pipelines or other automated code scanning workflows.

## Supported Languages

The Secure Code Review tool supports static code analysis for the following languages:

- **Python**
- **C++**
- **Java**
- **PHP**
- **JavaScript**
- **Ruby**

## Key Components

### 1. **Static Code Analysis**
The tool scans source code files for potential security vulnerabilities by looking for known patterns and code smells associated with insecure coding practices. 

### 2. **Metadata Integration**
The scanning engine uses metadata to:
- Identify and map detected vulnerabilities to corresponding **CWE IDs**.
- Classify the vulnerabilities according to the **OWASP Top 10**.
- Provide a **severity rating** (e.g., Low, Medium, High) for each vulnerability.
- Offer **recommendations** for fixing identified issues.

### 3. **Detailed Reporting**
After the scan completes, the tool generates a detailed report that includes:
- **Vulnerability Details**: Each vulnerability is listed with its associated CWE ID, OWASP classification, severity level, and description.
- **Code Context**: The report includes the specific line of code where the vulnerability was detected, along with a snippet of the surrounding code for context.
- **Recommendations**: Practical, actionable recommendations on how to mitigate or fix the identified vulnerabilities.

The report is generated in an easy-to-read format (e.g., text or HTML), and both temporary and log files are saved for auditing purposes.

### 4. **Dependency**
The tool uses the ag (silver searcher) tool as its dependency, and using this tool was to aid aggressive searching of the piece of code to ensure accuracy in the vulnerability scan.

### 5. **Automation (Bash Script)**
The entire scanning process is encapsulated in a Bash script, which can be easily executed in a command-line environment. This script is designed for **automation** and can be integrated into **CI/CD** workflows to automatically scan code whenever changes are made. This helps catch security issues early in the development process.

### 6. **Log and Temporary Files**
For each scan, the tool generates:
- A **temporary file** containing the scan results, which can be inspected or saved for later use.
- A **log file** that records the detailed steps of the scan, useful for debugging, auditing, and ensuring transparency.

## Installation

To use the Secure Code Review tool, follow the steps below:

### Prerequisites:
- **Bash**: Ensure that Bash is installed on your system.
- **Python 3.x** (for Python code scanning).
- **Java** (for Java code scanning).
- **PHP** (for PHP code scanning).
- **C++ tools** (e.g., GCC) for C++ scanning.
- **Dependency Management**: Ensure that your system has access to dependency managers like `pip`, `npm`, or `composer`.


Certainly! Here’s an improved and well-structured version of the installation and usage steps in Markdown format for your GitHub repository README:

markdown
Copy code
## Installation and Usage

### Step 1: Clone the Repository
To get started, clone the repository to your local machine:

```bash
git clone https://github.com/your-repo/secure-code-review.git
cd secure-code-review

### Step 2: Install Dependencies
The tool requires The Silver Searcher (ag) for searching patterns in the codebase. Install it by running the following command:

sudo apt install silversearcher-ag

### Step 3: Run the Scan
Once the repository is cloned and dependencies are installed, you can run the scan by executing the provided Bash script:

./secure_code_review.sh /path/to/your/codebase
The script will automatically scan the specified codebase, identify vulnerabilities, and generate a detailed report with the findings.

### Step 4: Review the Results
After the scan completes, the results will be saved in a report file (e.g., scan_report.txt), and log/temporary files will be available for auditing. Review the generated report for detailed insights on the vulnerabilities found.

### Example Output
Here is a sample output of a vulnerability report:

[INFO] Scan completed successfully.
[INFO] 5 vulnerabilities found.

--- Vulnerability #1 ---
CWE: CWE-89: SQL Injection
OWASP: A1 - Injection
Severity: High
Line 42: sql_query = "SELECT * FROM users WHERE username = '" + user_input + "';"

Recommendation: Use prepared statements or parameterized queries to mitigate SQL injection risks.

--- Vulnerability #2 ---
CWE: CWE-79: Cross-Site Scripting (XSS)
OWASP: A7 - Cross-Site Scripting (XSS)
Severity: Medium
Line 78: print("<div>" + user_input + "</div>")

Recommendation: Sanitize or escape user input before rendering it in HTML.


