
# Scalable Identity and Access Management (IAM) Service
Production-Style IAM Platform | Spring Boot | Security-First Backend Engineering

This project is a production-style Identity and Access Management service built with Spring Boot and Spring Security.

It demonstrates how a real authentication system should handle:

- Authentication
- Authorization
- Token lifecycle management
- Abuse prevention
- Security auditing

The system emphasizes secure defaults, explicit failure handling, and defensive backend design.

---

# Key Capabilities

- JWT-based stateless authentication
- Refresh token rotation with reuse detection
- OAuth2 login (Google & GitHub)
- Redis-backed token bucket rate limiting
- Brute-force login protection
- Role-Based Access Control (RBAC)
- Security audit logging
- Concurrency-safe token rotation
- Docker deployment on AWS EC2

---

# High Level Architecture
```
            Client (Web / Mobile)
                     |
                     v
        +---------------------------+
        | Auth API (Spring Boot)    |
        +---------------------------+
                     |
                     v
    +-------------------------------------+
    | Spring Security Filter Chain        |
    | - JWT Authentication Filter         |
    | - OAuth2 Login                      |
    | - Rate Limiting Filter              |
    +-------------------------------------+
                     |
                     v
  +-------------------------------------------+
  | Application Services                      |
  | - Auth Service                            |
  | - Token Lifecycle Management              |
  | - OAuth Login Service                     |
  | - RBAC Authorization                      |
  | - Audit Logging                           |
  +-------------------------------------------+
                     |
                     v
  +-------------------------------------------+
  | Infrastructure Layer                      |
  | - PostgreSQL (Users, Tokens, Audit)       |
  | - Redis (Rate Limiting)                   |
  +-------------------------------------------+

```

# Authentication Flow

Login

1. User submits credentials
2. Password verified using BCrypt
3. Access token (JWT) issued with short TTL
4. Refresh token created and stored in database
5. Client uses access token for API requests

Token Refresh

Client → Refresh Token → Server Validation → New Access Token + New Refresh Token  
Old Refresh Token → revoked

Key properties:

- Access tokens are stateless JWT
- Refresh tokens are stored and rotated
- Reuse detection triggers revocation

---

# Token Lifecycle Security

Access Tokens
- JWT signed with HS256
- 15 minute expiration
- Stateless validation through Spring Security filters

Refresh Tokens
- Stored in PostgreSQL
- Hashed before persistence
- Rotated on every refresh
- Old tokens invalidated
- Single active refresh token per user
- Reuse detection triggers forced logout

Concurrency Safety
Refresh token rotation uses optimistic locking (@Version) to prevent race conditions during concurrent refresh attempts.

---

# Abuse Prevention & Rate Limiting

To mitigate automated attacks:

- Redis-backed Token Bucket rate limiting
- Login throttling
- Brute force protection
- CIDR/IP throttling
- Suspicious activity metrics

Redis provides low latency distributed counters suitable for authentication endpoints.

---

# Role Based Access Control (RBAC)

Entities:

User  
Role  
Permission  

Capabilities:

- Many-to-many user ↔ role mapping
- Permission bootstrap automation
- Method-level authorization via @PreAuthorize
- Admin APIs to manage roles and permissions

RBAC is designed to be data-driven and extensible.

---

# Security Audit Logging

The system records structured security events:

- Login success / failure
- OAuth authentication attempts
- Token refresh
- Logout
- Authorization decisions
- Failure severity

Audit records include:

- userId
- provider
- IP address
- user agent
- timestamp
- failure reason

Audit logs are stored in a database table for forensic traceability.

---

# Domain Driven Project Structure

src/main/java/com/jaypal/authapp

api – REST controllers  
domain – Core business domains  
service – Authentication workflows  
infrastructure – External integrations  
config – Spring configuration  
dto – Request / response models  
mapper – DTO mappers  
exception – Exception taxonomy  
event – Domain events  
listener – Async listeners  

---

# Core Database Entities

User  
Role  
Permission  
RefreshToken  
AuditLog  

Key Fields:

RefreshToken
- token_hash
- user_id
- expires_at
- revoked
- version

Database constraints enforce security invariants and referential integrity.

---

# Engineering Decisions

Why JWT instead of server sessions?
→ Stateless authentication enables horizontal scaling.

Why refresh token rotation?
→ Prevents replay attacks if refresh tokens leak.

Why hash refresh tokens?
→ Reduces impact if database is compromised.

Why Redis for rate limiting?
→ Low latency distributed counters for authentication endpoints.

Why optimistic locking?
→ Ensures only one refresh operation succeeds during concurrent requests.

---

# Running the Project

Requirements

- Java 21
- Maven
- PostgreSQL
- Redis

Setup

git clone https://github.com/Jaypal07/Scalable-Identity-Access-Management-IAM-Service
cd Scalable-Identity-Access-Management-IAM-Service
mvn clean install

Configuration

application-dev.yml  
.env

Run

mvn spring-boot:run

---

# Live Demo

http://3.110.155.78.nip.io:8080/about

---

# Author

Jaypal  
Backend Java Engineer (Transitioning from QA)

Focus Areas

- Spring Boot backend systems
- Security and authentication
- Identity management
- Failure-mode driven system design

GitHub  
https://github.com/Jaypal07  

LinkedIn  
https://www.linkedin.com/in/jaypal-koli/
