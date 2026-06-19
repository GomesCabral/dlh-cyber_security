# E-commerce Platform Threat Model

## System Overview

The system is an e-commerce platform where users can browse products, add items to a cart, checkout and pay, and view order history.


##  Architecture

```
User Browser
    |
    v
React Frontend
    |
    v
Node.js API Backend
    |
    v
PostgreSQL Database

Node.js API Backend
    |
    v
Stripe Payment Integration
```

## STRIDE Threats for Checkout Process

| Stride Category|Threat Description|Potential Impact| Suggested Mitigation
|----------------|-------------------------------|-----------------------------|----------------|
|Tampering|A user modifies the product price or cart total in the frontend request before checkout.|Financial loss, fraudulent purchases, incorrect order records. | Never trust frontend prices. Recalculate prices on the backend using product IDs from the database.            |
|Spoofing| An attacker uses stolen credentials or session tokens to checkout as another user. |Unauthorized purchases, account takeover, exposure of personal/order data.| Use MFA, secure session cookies, short token expiration, and suspicious login detection.
|Information Disclosure|Payment or personal data is exposed during checkout due to insecure transmission or excessive logging.|Leakage of sensitive customer data, legal/compliance issues, reputational damage.|Use HTTPS/TLS, do not store card details locally, rely on Stripe tokenization, and avoid logging sensitive payment data.


### Trust Boundaries
-   Validate all input on the **backend**.
-   Recalculate prices server-side.
-   Do not trust client-side data.

### React Frontend → Node.js API Backend

Data crosses from the frontend into the backend, where business logic is executed.

Example risk:

```
Frontend sends a checkout request with manipulated product quantities or IDs.
```

Mitigation:

-   Use authentication and authorization checks.
-   Validate request schemas.
-   Enforce business rules on the backend.

### Node.js API Backend → PostgreSQL Database

The backend sends queries to the database. If input is not handled safely, attackers may attempt SQL injection.

Example risk:

```
Search input contains SQL code that changes the intended database query.
```

Mitigation:

-   Use parameterized queries.
-   Use an ORM safely.
-   Apply least privilege to the database user.

### Node.js API Backend → Stripe

The system sends payment-related data to an external third-party service.

Example risk:

```
Payment request is intercepted or incorrectly validated.
```

Mitigation:

-   Use Stripe’s official SDK.
-   Verify Stripe webhooks.
-   Use HTTPS/TLS.
-   Never store raw credit card details.

## DREAD Scoring: SQL Injection in Product Search

Threat: SQL injection in product search functionality.

### DREAD Formula

```
Risk Score = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5
```

|DREAD Factor|Score| Justification
|----------------|-------------------------------|-----------------------------|
|Damage| 9 | SQL injection could expose product data, user data, order history, or possibly allow database modification.|
|Reproducibility| 8 |If the search field is vulnerable, the attack can likely be repeated easily with different payloads.
|Exploitability| 7 |Attackers can use common tools such as SQLMap or manually test payloads in the search bar.|
|Affected Users| 9 | A database compromise could affect many or all users of the platform.|
|Discoverability| 10 | Product search is public and easy to find because browsing products does not require authentication.

### Calculation

```
Risk Score = (9 + 8 + 7 + 9 + 10) / 5
Risk Score = 43 / 5
Risk Score = 8.6
```

### Risk Level

Critical

### Reasoning

A score of 8.6 is critical because the product search feature is publicly accessible, easy to discover, and could expose sensitive database information if exploited.

### Recommended Mitigations

-   Use parameterized SQL queries.
-   Validate and sanitize search input.
-   Use an ORM securely.
-   Limit database permissions for the application user.
-   Add logging and monitoring for suspicious search patterns.
-   Perform security testing using tools such as OWASP ZAP or SQLMap in a controlled environment.
