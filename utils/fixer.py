def get_fix(vulnerability, details=None):
    fixes = {
        "Injection": "Use parameterized queries and avoid direct user input in SQL or shell commands.",
        "Access Control": "Enforce proper role-based access control and validate user authorization for each action.",
        "Cryptographic Failures": "Use HTTPS, secure cookie flags, and strong encryption algorithms like AES-256.",
        "Security Misconfiguration": "Harden server configs, disable directory listings, and implement proper headers.",
        "Insecure Design": "Apply threat modeling and secure-by-design principles during development.",
        "Outdated Components": "Regularly patch and update all components and check for known CVEs.",
        "Auth Failures": "Implement multi-factor authentication and secure session handling.",
        "Integrity Failures": "Use signed packages and CI/CD verification tools.",
        "Logging & Monitoring": "Enable detailed audit logs and monitor for anomalies in real-time.",
        "SSRF": "Whitelist internal endpoints and validate all user-supplied URLs."
    }
    return fixes.get(vulnerability, "Follow secure coding best practices for this category.")
