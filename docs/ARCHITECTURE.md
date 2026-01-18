# Aura-Match: Project Architecture & System Overview

**Document Version:** 2.0  
**Status:** PRODUCTION READY — JWT-ONLY AUTH  
**Last Updated:** 2025-01

---

## 1. System Purpose

### What Aura-Match Is

Aura-Match is a **government-grade, fairness-first internship matching platform** that connects students with companies through AI-powered, system-owned intelligence. The platform ensures:

- Transparent, auditable matching decisions
- Equal opportunity for all candidates
- Protection against bias and manipulation
- Privacy-safe data exposure with consent-based access

### What Aura-Match Is NOT

- **NOT a job portal**: Students cannot browse companies or apply directly
- **NOT an ATS (Applicant Tracking System)**: Companies cannot filter or rank candidates manually
- **NOT a networking platform**: No direct messaging before mutual acceptance
- **NOT a bidding system**: Students cannot compete or rank preferences

---

## 2. Core Design Principles

### 2.1 System-Owned Intelligence

All matching logic, scores, and recommendations are computed by the system. Neither students nor companies can influence match outcomes directly. The AI matching engine is:

- Opaque to end users
- Deterministic given the same inputs
- Auditable by system administrators

### 2.2 Backend Authority

The backend is the **single source of truth** for all domain data. Frontend:

- Never computes business logic
- Never stores domain data locally (except auth tokens)
- Always fetches fresh state from backend
- Displays only what backend provides

### 2.3 Read-Only Frontend

Frontend components are display-only for system-owned data:

- Match scores: Read-only
- Offer status: Read-only (actions trigger backend mutations)
- Explanations: Read-only
- Timers/Countdowns: Display-only (backend enforces expiry)

### 2.4 Concurrency Safety

The system assumes:

- Multiple simultaneous users
- Race conditions on offers
- Network latency and failures

Therefore:

- All mutations are atomic
- Optimistic updates are forbidden for critical state
- Backend rejects invalid state transitions

### 2.5 Fairness & Auditability

Every decision must be:

- Traceable to input data
- Reproducible given same conditions
- Logged immutably
- Explainable (why, not how)

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Student   │  │   Company   │  │      Shared UI          │  │
│  │    Pages    │  │    Pages    │  │   (Components, Auth)    │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                     │                 │
│         └────────────────┼─────────────────────┘                 │
│                          │                                       │
│                   ┌──────▼──────┐                                │
│                   │   API Layer │  (axios + interceptors)        │
│                   └──────┬──────┘                                │
└──────────────────────────┼───────────────────────────────────────┘
                           │
                    HTTPS + JWT
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                         BACKEND                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                      API Gateway                             │ │
│  │         (Auth, Rate Limiting, Request Validation)           │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐ │
│  │                    Business Logic                            │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │ │
│  │  │   Auth   │  │  Resume  │  │  Offer   │  │   Matching   │ │ │
│  │  │ Service  │  │ Service  │  │ Service  │  │    Engine    │ │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘ │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼──────────────────────────────────┐ │
│  │                      Data Layer                              │ │
│  │         (PostgreSQL, Redis, File Storage)                    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 3.1 Frontend Responsibilities

| Responsibility | Description |
|----------------|-------------|
| Display data | Render backend-provided information |
| Collect input | Gather user input for backend submission |
| Navigation | Route users through flows |
| Auth token | Store and attach JWT (single token only) |
| Loading states | Show pending states during API calls |
| Error display | Show backend-provided error messages |

### 3.2 Backend Responsibilities

| Responsibility | Description |
|----------------|-------------|
| Authentication | Validate credentials, issue tokens |
| Authorization | Enforce role-based access |
| Data storage | Single source of truth for all entities |
| Business logic | All computations, validations, state machines |
| Privacy enforcement | Control data exposure based on relationship state |
| Matching engine | AI-powered candidate ranking (opaque) |
| Audit logging | Immutable record of all actions |

### 3.3 Auth Boundary (JWT-ONLY)

```
Frontend Storage:
├── localStorage
│   └── aura_access_token (JWT only)
│
Backend Validates:
├── Token signature
├── Token expiry
├── User role
└── Request authorization
```

### 3.4 Token Lifecycle (NO REFRESH TOKEN)

```
┌──────────────────────────────────────────────────────────────┐
│                   JWT-ONLY TOKEN FLOW                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Login/Register/OAuth                                     │
│     └── Backend returns: { access_token }                    │
│     └── Frontend stores JWT, calls /auth/me                  │
│                                                              │
│  2. API Request                                              │
│     └── Frontend attaches: Authorization: Bearer <token>     │
│                                                              │
│  3. Token Expired (401)                                      │
│     └── Frontend clears token → Redirect to /login           │
│     └── NO silent refresh, NO retry                          │
│                                                              │
│  4. Logout                                                   │
│     └── Frontend clears token → Redirect to /                │
│                                                              │
│  5. /auth/me is SINGLE SOURCE OF TRUTH                       │
│     └── All user state derived from /auth/me response        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.5 No Shared Business Logic

- Frontend contains ZERO business logic
- No score calculations
- No skill extraction
- No distance computation
- No eligibility checks
- No state transitions
- All logic lives in backend

---

## 4. User Roles

### 4.1 Student

| Capability | Allowed | Forbidden |
|------------|---------|-----------|
| Register with email/phone | ✓ | |
| Upload resume | ✓ | |
| Confirm extracted skills | ✓ | |
| Set preferences (domains, location) | ✓ | |
| View system-proposed offers | ✓ | |
| Accept/Decline offers | ✓ | |
| Flag matches for review | ✓ | |
| Withdraw application | ✓ | |
| | | Browse companies |
| | | Rank preferences |
| | | Contact companies directly |
| | | Modify match scores |
| | | Extend grace periods |

### 4.2 Company

| Capability | Allowed | Forbidden |
|------------|---------|-----------|
| Register with email | ✓ | |
| Create job postings | ✓ | |
| View system-proposed matches | ✓ | |
| Approve/Reject matches | ✓ | |
| Close job postings | ✓ | |
| | | Browse candidates |
| | | Search student database |
| | | Modify match scores |
| | | Contact students before acceptance |
| | | Override system decisions |

### 4.3 System (Matching Engine)

| Responsibility | Description |
|----------------|-------------|
| Skill extraction | Parse resumes, extract skills via NLP |
| Match computation | Rank candidates against job requirements |
| Offer generation | Create offers based on ranking |
| Expiry enforcement | Auto-expire offers past deadline |
| Auto-refill | Issue next-best offer when slot opens |
| Intake enforcement | Ensure accepted_count ≤ intake |
| Audit logging | Record all state transitions |

---

## 5. State Ownership Table

| Data Entity | Owner | Created By | Mutable By | Deleted By |
|-------------|-------|------------|------------|------------|
| User (Student) | Backend | Student (register) | Student (profile only) | System |
| User (Company) | Backend | Company (register) | Company (profile only) | System |
| Resume | Backend | Student (upload) | Student (new version) | Student |
| Skills | Backend | System (extraction) | Student (confirm) | Student |
| Preferences | Backend | Student | Student | Student |
| Job | Backend | Company | Company (limited) | Company/System |
| Match | Backend | System | System only | System |
| Offer | Backend | System | System only | System |
| Review Request | Backend | Student (submit) | System only | Never |
| Application State | Backend | System | System only | System |
| Audit Log | Backend | System | Never | Never |

---

## 6. Lifecycle Overview

### 6.1 Student Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    STUDENT LIFECYCLE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. REGISTRATION                                                │
│     └── Email + Password → Email OTP → Phone OTP                │
│         Status: profile-pending                                 │
│                                                                 │
│  2. PROFILE COMPLETION                                          │
│     └── Personal details + Resume upload                        │
│         Status: skills-pending                                  │
│                                                                 │
│  3. SKILL CONFIRMATION                                          │
│     └── Review AI-extracted skills → Confirm/Edit               │
│         Status: preferences-pending                             │
│                                                                 │
│  4. PREFERENCES SET                                             │
│     └── Domains, work style, location, stipend                  │
│         Status: submitted                                       │
│                                                                 │
│  5. MATCHING                                                    │
│     └── System processes → Generates offers                     │
│         Status: processing → matched/waitlist/rejected          │
│                                                                 │
│  6. OFFER RESPONSE                                              │
│     └── Accept (one) / Decline / Let expire                     │
│         Status: confirmed / seeking-alternative                 │
│                                                                 │
│  7. COMPLETION                                                  │
│     └── Mutual acceptance → Data unlocked                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Company Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPANY LIFECYCLE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. REGISTRATION                                                │
│     └── Email + Company details → Email OTP                     │
│         Status: profile-pending                                 │
│                                                                 │
│  2. PROFILE COMPLETION                                          │
│     └── Contact person, GST number                              │
│         Status: active                                          │
│                                                                 │
│  3. JOB CREATION                                                │
│     └── Title, skills, location, intake, JD                     │
│         Job Status: draft → processing                          │
│                                                                 │
│  4. MATCHING                                                    │
│     └── System analyzes JD → Ranks candidates                   │
│         Job Status: matched                                     │
│                                                                 │
│  5. CANDIDATE VALIDATION                                        │
│     └── Approve/Reject system proposals                         │
│         (System issues offers to approved candidates)           │
│                                                                 │
│  6. INTAKE FULFILLED                                            │
│     └── accepted_count == intake                                │
│         Job Status: closed                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 Offer Lifecycle (State Machine)

```
                    ┌─────────────┐
                    │   OFFERED   │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
   ┌──────────┐     ┌──────────┐     ┌───────────┐
   │ ACCEPTED │     │ DECLINED │     │  EXPIRED  │
   └──────────┘     └──────────┘     └───────────┘
         │                                  │
         │                                  │
         ▼                                  ▼
   ┌──────────┐                      ┌───────────┐
   │ TERMINAL │                      │  TERMINAL │
   └──────────┘                      └───────────┘

   ┌───────────┐
   │ WITHDRAWN │ ◄── Can occur from OFFERED only
   └───────────┘
         │
         ▼
   ┌──────────┐
   │ TERMINAL │
   └──────────┘
```

**Allowed Transitions:**

| From | To | Trigger |
|------|-----|---------|
| offered | accepted | Student accepts within grace period |
| offered | declined | Student declines |
| offered | expired | Grace period ends (system) |
| offered | withdrawn | Student withdraws application |

**Forbidden Transitions:**

- accepted → any
- declined → any
- expired → any
- withdrawn → any

### 6.4 Review/Flag Lifecycle

```
┌──────────────┐
│  SUBMITTED   │ ◄── Student creates flag
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ UNDER_REVIEW │ ◄── System/Admin picks up
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   RESOLVED   │ ◄── Decision made
└──────────────┘
```

- Student can submit ONE review per match
- No edits after submission
- Resolution is system-owned

---

## 7. Explicit Non-Goals

### 7.1 What Frontend Will NEVER Do

| Action | Reason |
|--------|--------|
| Compute match scores | System-owned intelligence |
| Parse resumes | Backend AI responsibility |
| Extract skills | Backend NLP responsibility |
| Calculate distances | Privacy + backend authority |
| Determine eligibility | Business logic lives in backend |
| Expire offers | Backend enforces time |
| Modify offer state directly | State machine is backend-owned |
| Store domain data | Backend is source of truth |
| Generate OTPs | Security-critical |
| Validate credentials | Backend authentication |

### 7.2 What Backend MUST Enforce

| Invariant | Enforcement |
|-----------|-------------|
| accepted_count ≤ intake | Atomic transaction on accept |
| Grace period expiry | Scheduled job + accept-time check |
| Single active acceptance | Reject duplicate accepts |
| Resume version binding | Match stores resumeId + version |
| Privacy before acceptance | Filter response fields |
| Cooldown after withdrawal | Block resubmission for N days |
| Audit trail | Immutable append-only log |
| State machine validity | Reject invalid transitions |

---

## Appendix A: System Invariants (NON-NEGOTIABLE)

These rules MUST be enforced by backend. Violation indicates system failure.

### Job Intake Invariants

```
For every Job:
  1. accepted_count ≤ intake                    (ALWAYS)
  2. active_offers + accepted_count ≥ intake    (ALLOWED - oversubscription)
  3. accepted_count > intake                    (FORBIDDEN - SYSTEM FAILURE)
  
  When accepted_count == intake:
    - Job.status MUST transition to "closed"
    - NO new offers may be created
    - Pending offers MUST be auto-expired
```

### Offer State Machine

```
Valid States: offered, accepted, declined, expired, withdrawn

Valid Transitions:
  offered → accepted
  offered → declined
  offered → expired
  offered → withdrawn

Terminal States: accepted, declined, expired, withdrawn
  - No transitions from terminal states
  - Any attempt MUST return HTTP 409
```

### Grace Period Rules

```
1. Every offer MUST have expiresAt timestamp
2. Backend MUST check expiry on every accept attempt
3. Frontend countdown is DISPLAY ONLY
4. If now > expiresAt at accept time:
   - Transition offer to expired
   - Return HTTP 409 OFFER_EXPIRED
```

### Auto-Refill Guarantee

```
IF any of:
  - offer declined
  - offer expired
  - offer withdrawn
  - student cooldown triggered

AND accepted_count < intake

THEN:
  - System MUST issue next-best offer from ranked queue
  - Selection MUST be deterministic
  - Refill MUST be automatic and idempotent
```

### Concurrency Rules

```
1. Job-level locking during:
   - offer acceptance
   - offer creation
   - refill execution

2. Acceptance MUST be atomic:
   - Check accepted_count
   - Check offer validity
   - Check expiry
   - Increment accepted_count
   - Transition offer to accepted
   - Close job if intake met
   ALL in ONE transaction

3. Simultaneous accepts:
   - One succeeds (200)
   - Others fail (409 INTAKE_FULL or OFFER_EXPIRED)
```

### Forbidden States

The following states MUST NEVER occur:

- Two accepted offers when intake = 1
- Accepted offer with timestamp > expiresAt
- Job closed with accepted_count < intake (unless manually closed)
- Pending offers when job is closed
- Same student with two accepted offers for same job
- Offer in non-terminal state after expiresAt passed

---

## Appendix B: Observability Requirements

Backend MUST log (immutably):

| Event | Required Fields |
|-------|-----------------|
| Offer created | offerId, jobId, studentId, expiresAt, timestamp |
| Offer accepted | offerId, studentId, timestamp |
| Offer declined | offerId, studentId, timestamp |
| Offer expired | offerId, triggeredBy (system/cron), timestamp |
| Offer withdrawn | offerId, studentId, timestamp |
| Accept rejected | offerId, reason (EXPIRED/INTAKE_FULL/INVALID), timestamp |
| Refill triggered | jobId, newOfferId, previousOfferId, timestamp |
| Job closed | jobId, reason (intake_met/manual), accepted_count, timestamp |

---

**END OF DOCUMENT A**
