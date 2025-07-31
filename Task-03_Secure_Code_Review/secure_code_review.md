Secure Code Review – OWASP Juice Shop

Objective
This task involved reviewing the source code of a Node.js-based web app (Juice Shop) to identify security flaws and recommend fixes.

---

Finding 1: Hardcoded JWT Secret

- File: `server.ts`
- Issue: JWT secret is hardcoded in the source code.
- Risk: If an attacker gains access to the codebase, they can forge valid tokens.
- Recommendation: Store the secret in an environment variable like `process.env.JWT_SECRET`.

---

Finding 2: Stored XSS in Product Review

- File: `product-review.component.ts`
- Issue: User input is rendered directly without sanitization.
- Risk: Attackers can inject malicious JavaScript that executes for other users.
- Recommendation: Sanitize user input using Angular’s built-in tools or libraries like DOMPurify.

---

Finding 3: Unvalidated Input in Complaint Form

- File: `routes/complaints.ts`
- Issue: The `message` field in the complaint form is not validated or sanitized.
- Risk: Could lead to injection attacks or denial of service.
- Recommendation: Use middleware like `express-validator` to validate input length and content.
