Secure SIS: Project Documentation
This repository contains the implementation and design documentation for
the Online Secure Student Information System, developed as part of the
Secure Software Engineering course (Spring 2025-2026).
1. Quick Start
To run the secure login implementation locally:
# Install dependencies
pip install -r requirements.txt
# Launch the secure login server
python secure_login.py
Access the portal at: http://127.0.0.1:5000/login
2. Demo Credentials
Email: student@example.com
Password: Student123!
3. Security Controls Implemented
Following the project requirements and threat model (STRIDE), the following
controls are demonstrated in secure_login.py :
SQL Injection Defense: Use of parameterized SQLite queries for all
database interactions [SR-2].
Credential Safety: Salted password hashing using Werkzeug's secure
implementation [SR-1].
•
•
•
•
Brute-Force Mitigation: Rate limiting and account lockout after 5 failed
attempts [SR-9].
Session Security: Secure cookie flags (HttpOnly, SameSite) and session
regeneration upon login [SR-4].
CSRF Protection: Token validation for all POST requests [SR-7].
Input Integrity: Strict server-side validation and normalization of email and
password fields [SR-5].
Information Leakage Prevention: Generic error messages to prevent
account enumeration [SR-10].
4. Repository Contents
secure_login.py : The defensive Flask implementation of the login
process.
requirements.txt : Project dependencies.
Final_Secure_SIS_Project_Report.pdf : Comprehensive security
analysis, threat model, and test plan.
Secure_SIS_Presentation.pptx : Executive summary and design
overview.
•
•
•
•
•
•
•
•
• 
