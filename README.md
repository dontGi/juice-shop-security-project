\# Juice Shop Security Assessment

This repository contains the security fixes and assessment work done on the OWASP Juice Shop web application. The goal of this project was to identify vulnerabilities, apply security best practices, and document the entire process as part of a 3-week learning journey.

\---

\#\#  Project Summary

The OWASP Juice Shop is intentionally vulnerable for learning purposes. Over the course of 3 weeks, I explored the codebase, used tools to find vulnerabilities, and applied secure coding techniques to patch them.

\---

\#\#  Security Fixes & Enhancements

\- ✔️ Input validation for user inputs  
\- ✔️ Password hashing using \`bcrypt\`  
\- ✔️ JWT implementation for secure user authentication  
\- ✔️ Use of \`helmet\` for securing HTTP headers  
\- ✔️ Integrated logging using \`winston\` in routes like \`login.js\`  
\- ✔️ Tested and prevented SQL Injection  
\- ✔️ Removed XSS vulnerabilities

\---

\#\#  Tools Used

\- \*\*bcrypt\*\*  
\- \*\*jsonwebtoken\*\*  
\- \*\*helmet\*\*  
\- \*\*winston\*\*  
\- \*\*Burp Suite\*\*  
\- \*\*OWASP ZAP\*\*  
\- \*\*Manual browser testing\*\*

\---

\#\#  Included Files

| File Name  | Description  |
| :---- | :---- |
| logger.js | Winston logger configuration    |
| login .js |  Modified login route with logger   |
| app.js |  |
| checklist.md | Final security checklist  |
| README.md | Project summary and documentation   |
| assessment\_report.pdf | Security report with explanation & screenshots |
| security.log | Example log file from Winston         |
| screenshots | Folder with proof-of-fix screenshots |

\#\#  Screenshots

All screenshots of before-and-after fixes, Burp Suite scans, and browser views are added in the \`screenshots/\` folder and embedded inside \`assessment\_report.pdf\`.

\---

\#\#  Challenges & Learnings

\- Understood real-world vulnerabilities in web applications.  
\- Learned to use tools like ZAP and Burp Suite effectively.  
\- Practiced secure coding using Node.js and Express.  
\- Faced and overcame issues with encoding, JWT handling, and middleware security.

\---

\#\#  How to Run This

If you want to test this setup:

1\. Clone the repo:  
   \`\`\`bash  
   git clone  https://github.com/dontGi/juice-shop-security-project.git
   cd juice-shop-security

