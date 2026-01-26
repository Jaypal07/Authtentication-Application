# Scalable Identity and Access Management (IAM) Service  
**Production-Grade Authentication, Authorization, and Security Platform**  
Built with **Java 21, Spring Boot 3, Spring Security, OAuth2, PostgreSQL, Redis**

This is a **real IAM backend**, not a tutorial project.

It implements **secure authentication flows**, **refresh token rotation**, **OAuth2 federation**, **RBAC enforcement**, **rate limiting**, **token introspection**, **audit state machines**, **email-based account lifecycle**, and **defensive failure handling**.

Built to demonstrate **production security engineering**, **IAM system design**, and **backend maturity**.

---

## What This Project Demonstrates

Most IAM demos simplify or ignore real-world threats.  
This system models **real security risks and real mitigations**:

- Short-lived JWT access tokens  
- Stateful refresh tokens with **rotation and replay protection**  
- Token introspection API  
- OAuth2 login with provider-aware identity mapping  
- Role- and permission-based access control (RBAC)  
- Brute-force and abuse rate limiting (Redis-backed)  
- Structured authentication audit logging  
- Optimistic locking to prevent token race attacks  
- Email verification and password reset workflows  
- Security-first exception and failure modeling  
- Domain-driven backend architecture  

This repository proves **security judgment, not framework usage**.

---

## High-Level Architecture

```text
+------------------------+        +---------------------------+
| Client (Web / Mobile)  | -----> | Auth API (Spring Boot)    |
+------------------------+        +---------------------------+
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
             +---------------------------------------------------+
             | Application & Domain Services                     |
             | - Auth Service                                    |
             | - Token Issuer & Refresh Lifecycle                |
             | - OAuth Login Service                             |
             | - RBAC Authorization                              |
             | - Email Verification & Password Reset             |
             | - Audit Logging & Security Telemetry              |
             +---------------------------------------------------+
                                           |
                                           v
             +---------------------------------------------------+
             | Persistence & Infrastructure Layer               |
             | - PostgreSQL (Users, Roles, Tokens, Audit)        |
             | - Redis (Rate Limits, Cache)                      |
             +---------------------------------------------------+
```

---

## Domain-Driven Project Structure

```text
src/main/java/com/jaypal/authapp
├── api                    # REST Controllers (Auth, User, Admin)
│   ├── auth
│   ├── user
│   └── admin
│
├── domain                 # Core business domains
│   ├── audit              # Auth audit logs & invariants
│   ├── token              # Refresh token lifecycle & security
│   └── user               # Users, Roles, Permissions
│
├── service                # Application services & auth operations
│   ├── auth               # Login, logout, refresh, verification
│   ├── oauth              # OAuth federation services
│   └── operations         # Auth orchestration flows
│
├── infrastructure         # External system integrations
│   ├── audit              # Audit context & resolution
│   ├── email              # Email delivery & templates
│   ├── oauth              # OAuth provider handlers
│   ├── ratelimit          # Redis-backed rate limiting
│   ├── security           # Filters, JWT, token extraction
│   └── utils              # Cookie & token utilities
│
├── config                 # Security, Redis, Async, Web config
├── mapper                 # DTO and OAuth user mappers
├── dto                    # Request/response models
├── exception              # Structured domain exceptions
├── event                  # Domain events
├── listener               # Async event listeners
└── AuthAppApplication.java
```

---

## Core Features

### Authentication
- Email and password login  
- OAuth2 login (Google and GitHub)  
- BCrypt password hashing  
- Email verification workflow  
- Password reset and secure token validation  
- Token introspection endpoint  

### Token Lifecycle & Session Security

**Access Tokens**
- JWT signed with HS256  
- 15-minute TTL  
- Stateless validation  

**Refresh Tokens**
- Stored in PostgreSQL  
- Rotated on every refresh  
- Replay and reuse detection  
- Optimistic locking for concurrency protection  
- Revocation and forced logout support  
- Token hashing for breach safety  

---

## Running the Project Locally

### Prerequisites
- Java 21  
- Maven  
- PostgreSQL  
- Redis  

### Setup

```bash
git clone https://github.com/Jaypal07/Scalable-Identity-Access-Management-IAM-Service
cd Scalable-Identity-Access-Management-IAM-Service
mvn clean install
```

### Configure Environment

- application-dev.yml  
- .env (Database, Redis, OAuth secrets)

### Run

```bash
mvn spring-boot:run
```

---

## Author

**Jaypal**  
Backend Engineer focused on **Security, Scalability, and System Correctness**  

GitHub: https://github.com/Jaypal07  
