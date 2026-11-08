# Security Policy

CloudSentinel treats security as a product requirement. This policy records development expectations; it does not claim a security support SLA or identify a reporting contact that is not present in the repository.

## Security-first development

Follow least privilege, defense in depth, secure defaults, backend authorization, organization-level tenant isolation, evidence integrity, and auditability. Security-sensitive features must include direct tests for relevant threats, including authentication, authorization, IDOR, tenant isolation, SSRF, secret exposure, and unsafe input where applicable.

## Secrets and credentials

- Never commit passwords, API keys, AWS secret keys, access tokens, session secrets, private credentials, or real production configuration.
- Example environment files must contain placeholders only.
- Never log credentials or tokens, expose cloud credentials to frontend code, or store secrets in evidence.
- Prefer AWS STS AssumeRole with a read-only security role. Permanent AWS access keys are not the default integration mechanism.
- Use secure local configuration for development and an appropriate secret-management mechanism in production.

## Vulnerability reporting and responsible disclosure

Do not disclose an unpatched vulnerability publicly or use it to access data or systems beyond what is necessary to demonstrate the issue. Provide a clear description, affected component/version or commit when known, impact, and reproducible steps to the repository maintainers through the private reporting channel designated by the repository owner. No reporting email or other contact is currently published in this repository; do not assume or invent one. Allow maintainers reasonable time to investigate and coordinate a fix before public disclosure.

## Supported security practices

The project intends to use Ruff, MyPy, Pytest, Bandit, pip-audit, Semgrep, and Trivy as scoped by its CI/security phases. These tools complement, but do not replace, architecture review, code review, tenant-isolation tests, and security testing. Report suspected vulnerabilities privately rather than as public issues when the hosting platform provides a private security advisory mechanism.
