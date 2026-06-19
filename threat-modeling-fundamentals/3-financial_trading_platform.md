# Financial Trading Platform Threat Model

## System Overview

The system is a financial trading platform that allows users to view real-time stock prices, execute buy/sell orders, transfer funds, and configure automated trading rules.

### Requirements

-   High availability: 99.99% uptime
-   Low latency: less than 100ms for trades
-   Regulatory compliance: SEC and FINRA

##  Architecture

```
User Device
    |
    v
Trading Application
    |
    v
Trading API
    |
    +---------------+
	|				|
    v				v
Trading Engine	User Database
    |
    v
Financial Markets


Automated Rules Engine
    |
    v
Order Execution System
```

### Most Critical CIA Component

The most critical CIA component for a financial trading platform is:

### Integrity

**Why Integrity is the Priority**

Integrity ensures that information remains accurate and cannot be modified without authorization.

In a trading system, incorrect or manipulated data can cause severe financial damage.

Examples:

-   Changing a buy order from:

Buy 10 shares

to:

Buy 10,000 shares

-   Changing the destination account for a funds transfer
-   Modifying automated trading rules

A confidentiality breach is serious, but incorrect transactions can immediately create financial loss.

---

### CIA Analysis
| CIA Component | Importance | Example Risk
|--------------------|---------------|------
| Confidentiality | High | Attackers steal account information or trading strategies
| Integrity | Critical | Attackers modify trades, balances, or trading rules
| Availability | Very High | Users cannot trade during market hours
---


### Can Security Conflict With Performance?

Yes.

Security controls can sometimes increase latency.

**Examples**:

**Encryption**

Security benefit:

-   Protects data confidentiality

Performance cost:

-   Additional processing time

---

### Fraud Detection

Security benefit:

-   Blocks suspicious trades

Performance cost:

-   Extra checks before executing orders
---

### Logging and Compliance Checks

Security benefit:

-   Creates audit evidence

Performance cost:

-   Additional storage and processing

Because trades require less than 100ms latency, security controls must be optimized.

Solutions:

-   Fast authentication tokens
-   Efficient encryption
-   Real-time monitoring
-   Asynchronous logging
---

### Threat Model: Automated Trading Rules Feature

Automated trading rules allow users to create conditions like:

Example:

```
If stock price < $100
Automatically buy 50 shares
```

This feature is dangerous because actions happen without human confirmation.

---

### Risk 1: Unauthorized Rule Modification

**STRIDE Category**

Spoofing / Tampering

**Threat Description**

An attacker changes a user's automated trading rules.

**Attack Scenario**

1.  Attacker steals account credentials.
2.  Attacker modifies an existing rule.

**Original**:

```
Buy 10 Apple shares if price drops 5%
```

**Modified**:

```
Sell all Apple shares immediately
```

**Impact**

-   Financial loss
-   Unauthorized transactions
-   Loss of customer trust

**Mitigation**

-   Require MFA for rule changes
-   Send change notifications
-   Require confirmation for high-risk rules
-   Maintain rule change history
---

### Risk 2: Trading Logic Flaws

**STRIDE Category**

Tampering

**Threat Description**

Poorly designed trading rules behave unexpectedly.

**Attack Scenario**

A user creates:

```
If price increases:
    buy shares
```

A bug creates an infinite trading loop.

**Impact**

-   Massive unwanted trades
-   Financial loss
-   Market compliance violations

**Mitigation**

-   Validate trading rules before activation
-   Apply transaction limits
-   Test rules in simulation mode
-   Add circuit breakers
---

### Risk 3: Race Conditions

**STRIDE Category**

Tampering / Elevation of Privilege

**Threat Description**

Multiple trades execute at the same time and create inconsistent results.

**Attack Scenario**

Two automated rules execute simultaneously:

Rule 1:

Sell 100 shares

Rule 2:

Sell same 100 shares again

**Impact**

-   Incorrect account balances
-   Invalid trades
-   Financial errors

**Mitigation**

-   Transaction locking
-   Atomic database operations
-   Trade validation before execution
-   Concurrency controls
---

### Defense-in-Depth After Account Compromise

Scenario:

An attacker successfully logs into a user account.

Security must reduce the damage.

---
### Layer 1: Multi-Factor Authentication

Purpose:

Prevent account takeover even if passwords are stolen.

Protection:

-   Hardware keys
-   Authentication apps
-   Biometric verification

---

### Layer 2: Session Management

Purpose:

Control active user sessions.

Controls:

-   Short session expiration
-   Device verification
-   Logout suspicious sessions

Example:

A login from a new country requires verification.

---

### Layer 3: Transaction Limits

Purpose:

Limit financial damage.

Examples:

-   Maximum daily transfer amount
-   Maximum trade size
-   Withdrawal limits

---

### Layer 4: Anomaly Detection

Purpose:

Detect unusual behavior.

Examples:

Normal:

```
User buys €500/month
```

Suspicious:

```
Suddenly sells €100,000 in assets
```

Actions:

-   Pause transaction
-   Require verification
-   Alert security team

---

### Layer 5: Authorization Controls

Purpose:

Require additional approval for sensitive actions.

Examples:

Require confirmation for:

-   Bank account changes
-   Large withdrawals
-   Automated rule modifications

---

### Layer 6: Audit Logging

Purpose:

Maintain evidence of all actions.

Record:

-   User ID
-   IP address
-   Timestamp
-   Action performed

Benefits:

-   Incident investigation
-   Compliance
-   Fraud detection

---

### Layer 7: Notification System

Purpose:

Alert users quickly.

Examples:

Send alerts when:

-   New login occurs
-   Trading rules change
-   Large transactions happen

---
### Defense-in-Depth Summary

| Layer | Protection
|--------|-----------
| MFA | Prevent stolen password abuse
| Session Security | Stops unauthorized sessions
| Transaction Limits | Reduces financial damage
| Anomaly Detection | Finds suspicious behavior
| Authorization Checks | Blocks dangerous actions
| Audit Logging | Provides investigation evidence
| Notifications | Allows fast user response
---
### Conclusion

For a trading platform:

-   Integrity is the highest priority because incorrect trades can cause immediate financial loss.
-   Availability is also critical because users need access during market hours.
-   Automated trading requires strong controls because mistakes execute automatically.
-   Defense-in-depth ensures that one security failure does not lead to complete compromise.
