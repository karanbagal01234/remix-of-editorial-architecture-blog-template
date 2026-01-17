# Aura-Match: Backend API Contract Specification

**Document Version:** 1.0  
**Status:** FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH  
**Base URL:** `/api/v1`  
**Content-Type:** `application/json`

---

## Table of Contents

1. [Authentication APIs](#1-authentication-apis)
2. [Student APIs](#2-student-apis)
3. [Resume APIs](#3-resume-apis)
4. [Offer APIs](#4-offer-apis)
5. [Review APIs](#5-review-apis)
6. [Application APIs](#6-application-apis)
7. [Company APIs](#7-company-apis)
8. [Job APIs](#8-job-apis)
9. [Matching APIs](#9-matching-apis)
10. [Error Codes Reference](#10-error-codes-reference)

---

## 1. Authentication APIs

### 1.1 POST /auth/register

**DESCRIPTION:**  
Register a new user (student or company) with email and password.

**AUTH:** Not required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Valid email address |
| password | string | Yes | Minimum 8 characters |
| name | string | Yes | Full name (student) or company name |
| phone | string | Yes (student) | Phone number with country code |
| role | string | Yes | "student" or "company" |
| gstNumber | string | Yes (company) | GST registration number |

**RESPONSE (201 Created):**

```json
{
  "success": true,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "student",
    "emailVerified": false,
    "phoneVerified": false,
    "status": "profile-pending",
    "createdAt": "2024-01-15T10:00:00Z"
  },
  "access_token": "jwt_token",
  "refresh_token": "jwt_refresh_token"
}
```

**RESPONSE (400 Bad Request):**

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Invalid email format",
  "field": "email"
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "EMAIL_EXISTS",
  "message": "An account with this email already exists"
}
```

**STATE RULES:**
- Email must be unique across all users
- Password must be hashed before storage (bcrypt recommended)
- User status starts as "profile-pending"
- emailVerified and phoneVerified start as false

**FRONTEND BEHAVIOR:**
- On 201: Store tokens in localStorage, redirect to email verification
- On 400: Display field-specific validation error
- On 409: Display "email already exists" message

---

### 1.2 POST /auth/login

**DESCRIPTION:**  
Authenticate user with email and password.

**AUTH:** Not required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User email |
| password | string | Yes | User password |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "student",
    "emailVerified": true,
    "phoneVerified": true,
    "status": "submitted",
    "createdAt": "2024-01-15T10:00:00Z"
  },
  "access_token": "jwt_token",
  "refresh_token": "jwt_refresh_token"
}
```

**RESPONSE (401 Unauthorized):**

```json
{
  "error": "INVALID_CREDENTIALS",
  "message": "Invalid email or password"
}
```

**STATE RULES:**
- Compare password hash
- Generate new token pair on success
- Log failed attempts for security monitoring

**FRONTEND BEHAVIOR:**
- On 200: Store tokens, redirect based on user.status and user.role
- On 401: Display "invalid credentials" message

---

### 1.3 POST /auth/refresh

**DESCRIPTION:**  
Refresh access token using refresh token.

**AUTH:** Not required (refresh token in body)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| refresh_token | string | Yes | Valid refresh token |

**RESPONSE (200 OK):**

```json
{
  "access_token": "new_jwt_token"
}
```

**RESPONSE (401 Unauthorized):**

```json
{
  "error": "INVALID_REFRESH_TOKEN",
  "message": "Refresh token is invalid or expired"
}
```

**STATE RULES:**
- Validate refresh token signature and expiry
- Issue new access token only
- Refresh token remains valid until explicit logout

**FRONTEND BEHAVIOR:**
- On 200: Update access_token in localStorage, retry failed request
- On 401: Clear all tokens, redirect to /login

---

### 1.4 POST /auth/logout

**DESCRIPTION:**  
Invalidate current session.

**AUTH:** Required (student or company)

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true
}
```

**STATE RULES:**
- Invalidate refresh token (add to blacklist or delete from DB)
- Access token remains valid until expiry (stateless)

**FRONTEND BEHAVIOR:**
- On 200: Clear localStorage tokens, redirect to /

---

### 1.5 POST /auth/request-email-otp

**DESCRIPTION:**  
Request OTP to verify email address.

**AUTH:** Required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email to verify |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "message": "OTP sent to email",
  "expiresIn": 300
}
```

**RESPONSE (429 Too Many Requests):**

```json
{
  "error": "RATE_LIMITED",
  "message": "Too many OTP requests. Try again in 60 seconds",
  "retryAfter": 60
}
```

**STATE RULES:**
- Generate 6-digit OTP
- Store OTP with expiry (5 minutes)
- Rate limit: max 3 requests per 15 minutes
- Send via email service

**FRONTEND BEHAVIOR:**
- On 200: Navigate to OTP input screen, start 5-minute countdown
- On 429: Display retry countdown

---

### 1.6 POST /auth/verify-email-otp

**DESCRIPTION:**  
Verify email with OTP.

**AUTH:** Required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email being verified |
| otp | string | Yes | 6-digit OTP |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "emailVerified": true
}
```

**RESPONSE (400 Bad Request):**

```json
{
  "error": "INVALID_OTP",
  "message": "OTP is invalid or expired"
}
```

**STATE RULES:**
- Validate OTP matches and not expired
- Set user.emailVerified = true
- Delete OTP after successful verification
- Max 3 attempts per OTP

**FRONTEND BEHAVIOR:**
- On 200: Update user state, proceed to phone verification
- On 400: Display error, allow retry

---

### 1.7 POST /auth/request-phone-otp

**DESCRIPTION:**  
Request OTP to verify phone number.

**AUTH:** Required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| phone | string | Yes | Phone number with country code |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "message": "OTP sent to phone",
  "expiresIn": 300
}
```

**STATE RULES:**
- Same as email OTP
- Send via SMS service

**FRONTEND BEHAVIOR:**
- Same as email OTP

---

### 1.8 POST /auth/verify-phone-otp

**DESCRIPTION:**  
Verify phone with OTP.

**AUTH:** Required

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| phone | string | Yes | Phone being verified |
| otp | string | Yes | 6-digit OTP |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "phoneVerified": true
}
```

**STATE RULES:**
- Same as email verification
- Set user.phoneVerified = true

**FRONTEND BEHAVIOR:**
- On 200: Update user state, proceed to profile completion

---

### 1.9 GET /auth/session

**DESCRIPTION:**  
Get current user session and profile.

**AUTH:** Required

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "phone": "+91XXXXXXXXXX",
    "role": "student",
    "emailVerified": true,
    "phoneVerified": true,
    "status": "submitted",
    "createdAt": "2024-01-15T10:00:00Z"
  }
}
```

**RESPONSE (401 Unauthorized):**

```json
{
  "error": "UNAUTHORIZED",
  "message": "Invalid or expired token"
}
```

**STATE RULES:**
- Validate access token
- Return fresh user data from database

**FRONTEND BEHAVIOR:**
- On 200: Initialize app state with user data
- On 401: Clear tokens, redirect to /login

---

## 2. Student APIs

### 2.1 GET /student/profile

**DESCRIPTION:**  
Get current student profile.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "id": "uuid",
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+91XXXXXXXXXX",
  "location": {
    "lat": 12.9716,
    "lng": 77.5946
  },
  "skills": ["React", "TypeScript", "Node.js"],
  "resume": {
    "id": "resume-uuid",
    "version": 2,
    "uploadedAt": "2024-01-15T10:00:00Z",
    "isActive": true
  },
  "preferences": {
    "domains": ["Technology", "Finance"],
    "workStyle": "hybrid",
    "distance": 25,
    "stipend": 15000
  },
  "status": "submitted",
  "emailVerified": true,
  "phoneVerified": true,
  "onboardingComplete": true,
  "createdAt": "2024-01-01T10:00:00Z"
}
```

**STATE RULES:**
- Return only authenticated student's data
- Mask sensitive fields if profile incomplete

**FRONTEND BEHAVIOR:**
- On 200: Populate UI with profile data

---

### 2.2 PATCH /student/profile

**DESCRIPTION:**  
Update student profile fields.

**AUTH:** Required (student)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | Full name |
| phone | string | No | Phone number |
| location | object | No | { lat: number, lng: number } |

**RESPONSE (200 OK):**

```json
{
  "id": "uuid",
  "name": "John Doe Updated",
  "phone": "+91XXXXXXXXXX",
  "location": {
    "lat": 12.9716,
    "lng": 77.5946
  },
  "status": "skills-pending"
}
```

**RESPONSE (400 Bad Request):**

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Invalid phone number format"
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "PROFILE_LOCKED",
  "message": "Profile cannot be modified after submission"
}
```

**STATE RULES:**
- Profile updates allowed only before submission
- After status = "submitted", profile is locked
- Status transitions: profile-pending → skills-pending (on first profile save with resume)

**FRONTEND BEHAVIOR:**
- On 200: Update local state, show success toast
- On 409: Display "profile locked" message, disable form

---

### 2.3 POST /student/skills/extract

**DESCRIPTION:**  
Request AI extraction of skills from resume.

**AUTH:** Required (student)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| resumeId | string | Yes | ID of resume to analyze (or "current" for active) |

**RESPONSE (200 OK):**

```json
{
  "skills": ["React", "TypeScript", "Node.js", "PostgreSQL", "AWS"],
  "confidence": {
    "React": 0.95,
    "TypeScript": 0.92,
    "Node.js": 0.88,
    "PostgreSQL": 0.75,
    "AWS": 0.70
  },
  "extractedFrom": {
    "resumeId": "resume-uuid",
    "version": 2
  }
}
```

**RESPONSE (404 Not Found):**

```json
{
  "error": "RESUME_NOT_FOUND",
  "message": "No active resume found"
}
```

**STATE RULES:**
- Backend runs NLP/AI extraction
- Frontend NEVER parses resume
- Store extracted skills temporarily until confirmation
- Link extraction to specific resume version

**FRONTEND BEHAVIOR:**
- On 200: Display skills for student confirmation
- On 404: Redirect to profile page to upload resume

---

### 2.4 POST /student/skills/confirm

**DESCRIPTION:**  
Confirm final skill set after review.

**AUTH:** Required (student)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| skills | string[] | Yes | Final confirmed skills |

**RESPONSE (200 OK):**

```json
{
  "skills": ["React", "TypeScript", "Node.js"],
  "confirmedAt": "2024-01-15T10:00:00Z",
  "status": "preferences-pending"
}
```

**RESPONSE (400 Bad Request):**

```json
{
  "error": "EMPTY_SKILLS",
  "message": "At least one skill is required"
}
```

**STATE RULES:**
- Minimum 1 skill required
- Status transitions: skills-pending → preferences-pending
- Skills are immutable after submission
- Store confirmed skills with timestamp

**FRONTEND BEHAVIOR:**
- On 200: Navigate to preferences page
- On 400: Display validation error

---

### 2.5 POST /student/preferences

**DESCRIPTION:**  
Save student preferences.

**AUTH:** Required (student)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| domains | string[] | Yes | Preferred domains (1-3) |
| workStyle | string | Yes | "remote", "hybrid", "onsite" |
| distance | number | Yes | Max distance in km (if onsite/hybrid) |
| stipend | number | No | Minimum stipend expectation |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "preferences": {
    "domains": ["Technology", "Finance"],
    "workStyle": "hybrid",
    "distance": 25,
    "stipend": 15000
  },
  "status": "submitted"
}
```

**STATE RULES:**
- Status transitions: preferences-pending → submitted
- Once submitted, preferences are locked
- Submission triggers eligibility for matching pool

**FRONTEND BEHAVIOR:**
- On 200: Navigate to status page, show "submitted" confirmation

---

### 2.6 GET /student/domains

**DESCRIPTION:**  
Get available domains for preference selection.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "domains": [
    "Technology",
    "Finance",
    "Healthcare",
    "Education",
    "Manufacturing",
    "Retail",
    "Media",
    "Consulting"
  ]
}
```

**STATE RULES:**
- Return system-defined domain list
- List is read-only

**FRONTEND BEHAVIOR:**
- On 200: Populate domain selection UI

---

## 3. Resume APIs

### 3.1 POST /student/resume/upload

**DESCRIPTION:**  
Upload a new resume (creates new version).

**AUTH:** Required (student)

**REQUEST:**  
Content-Type: multipart/form-data

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| file | file | Yes | PDF file (max 5MB) |

**RESPONSE (201 Created):**

```json
{
  "id": "resume-uuid",
  "version": 2,
  "filename": "john_doe_resume.pdf",
  "uploadedAt": "2024-01-15T10:00:00Z",
  "isActive": true,
  "previousVersion": {
    "id": "old-resume-uuid",
    "version": 1,
    "isActive": false
  }
}
```

**RESPONSE (400 Bad Request):**

```json
{
  "error": "INVALID_FILE",
  "message": "Only PDF files are allowed"
}
```

**RESPONSE (413 Payload Too Large):**

```json
{
  "error": "FILE_TOO_LARGE",
  "message": "File size exceeds 5MB limit"
}
```

**STATE RULES:**
- Archive previous version (isActive = false)
- New version becomes active
- Version number increments
- Past matches retain link to their resume version
- Status transitions: profile-pending → skills-pending (if profile complete)

**FRONTEND BEHAVIOR:**
- On 201: Show success, trigger skill extraction
- On 400/413: Display error, allow retry

---

### 3.2 GET /student/resume/versions

**DESCRIPTION:**  
Get all resume versions for current student.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "versions": [
    {
      "id": "resume-uuid-2",
      "version": 2,
      "filename": "john_doe_resume_v2.pdf",
      "uploadedAt": "2024-01-15T10:00:00Z",
      "isActive": true,
      "usedInMatches": 0
    },
    {
      "id": "resume-uuid-1",
      "version": 1,
      "filename": "john_doe_resume.pdf",
      "uploadedAt": "2024-01-01T10:00:00Z",
      "isActive": false,
      "usedInMatches": 3
    }
  ]
}
```

**STATE RULES:**
- Return all versions, sorted by version descending
- Include match count per version
- Active version first

**FRONTEND BEHAVIOR:**
- On 200: Display version history with indicators

---

### 3.3 GET /student/resume/:resumeId

**DESCRIPTION:**  
Get specific resume metadata.

**AUTH:** Required (student or company with accepted match)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| resumeId | string | Resume UUID |

**RESPONSE (200 OK):**

```json
{
  "id": "resume-uuid",
  "version": 2,
  "filename": "john_doe_resume.pdf",
  "uploadedAt": "2024-01-15T10:00:00Z",
  "isActive": true,
  "downloadUrl": "https://storage.example.com/resumes/...",
  "expiresAt": "2024-01-15T11:00:00Z"
}
```

**RESPONSE (403 Forbidden):**

```json
{
  "error": "ACCESS_DENIED",
  "message": "Resume access not permitted before mutual acceptance"
}
```

**STATE RULES:**
- Student can always access own resumes
- Company can access ONLY after mutual acceptance
- Download URL is pre-signed with short expiry
- Privacy is backend-enforced

**FRONTEND BEHAVIOR:**
- On 200: Enable download link
- On 403: Display "access restricted" message

---

## 4. Offer APIs

### 4.1 GET /student/offers

**DESCRIPTION:**  
Get all offers for current student.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "offers": [
    {
      "id": "offer-uuid-1",
      "jobId": "job-uuid",
      "companyName": "TechCorp",
      "jobTitle": "Frontend Developer Intern",
      "status": "offered",
      "createdAt": "2024-01-15T10:00:00Z",
      "expiresAt": "2024-01-17T10:00:00Z",
      "matchScore": 87,
      "resumeVersion": 2
    },
    {
      "id": "offer-uuid-2",
      "jobId": "job-uuid-2",
      "companyName": "FinanceInc",
      "jobTitle": "Data Analyst Intern",
      "status": "expired",
      "createdAt": "2024-01-10T10:00:00Z",
      "expiresAt": "2024-01-12T10:00:00Z",
      "expiredAt": "2024-01-12T10:00:00Z",
      "matchScore": 82,
      "resumeVersion": 1
    }
  ]
}
```

**STATE RULES:**
- Return all offers regardless of status
- Include resume version used for each match
- Company name visible only for active/accepted offers
- Expired offers show historical data

**FRONTEND BEHAVIOR:**
- On 200: Display offers grouped by status

---

### 4.2 GET /student/offers/:offerId

**DESCRIPTION:**  
Get single offer details.

**AUTH:** Required (student)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| offerId | string | Offer UUID |

**RESPONSE (200 OK):**

```json
{
  "id": "offer-uuid",
  "jobId": "job-uuid",
  "companyId": "company-uuid",
  "companyName": "TechCorp",
  "jobTitle": "Frontend Developer Intern",
  "jobLocation": {
    "label": "Bangalore, Karnataka",
    "lat": null,
    "lng": null
  },
  "stipend": 20000,
  "status": "offered",
  "createdAt": "2024-01-15T10:00:00Z",
  "expiresAt": "2024-01-17T10:00:00Z",
  "matchScore": 87,
  "matchExplanation": [
    "Strong React and TypeScript skills match job requirements",
    "Location preference aligns with job posting",
    "Domain interest matches company sector"
  ],
  "resumeVersion": 2,
  "privacy": {
    "contactVisible": false,
    "exactLocationVisible": false,
    "fullResumeVisible": false
  }
}
```

**STATE RULES:**
- Privacy fields control what's visible
- Before acceptance: contact, exact location, resume hidden
- After acceptance: privacy fields become true
- matchExplanation is system-generated (read-only)

**FRONTEND BEHAVIOR:**
- On 200: Display offer card with countdown timer (display only)
- Show privacy restrictions clearly

---

### 4.3 POST /student/offers/:offerId/accept

**DESCRIPTION:**  
Accept an offer.

**AUTH:** Required (student)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| offerId | string | Offer UUID |

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "offer": {
    "id": "offer-uuid",
    "status": "accepted",
    "acceptedAt": "2024-01-16T09:00:00Z"
  },
  "expiredOffers": [
    {
      "id": "offer-uuid-2",
      "status": "expired",
      "reason": "SINGLE_ACCEPT_POLICY"
    }
  ],
  "privacy": {
    "contactVisible": true,
    "exactLocationVisible": true,
    "fullResumeVisible": true
  }
}
```

**RESPONSE (409 Conflict - Expired):**

```json
{
  "error": "OFFER_EXPIRED",
  "message": "This offer has expired",
  "expiredAt": "2024-01-17T10:00:00Z"
}
```

**RESPONSE (409 Conflict - Intake Full):**

```json
{
  "error": "INTAKE_FULL",
  "message": "This position has been filled"
}
```

**RESPONSE (409 Conflict - Already Accepted):**

```json
{
  "error": "ALREADY_ACCEPTED",
  "message": "You have already accepted an offer",
  "acceptedOfferId": "offer-uuid-other"
}
```

**STATE RULES:**

```
CRITICAL ATOMIC OPERATION:

1. Acquire job-level lock
2. Check offer.status == "offered"
3. Check now < expiresAt
4. Check job.accepted_count < job.intake
5. Check student has no other accepted offers
6. BEGIN TRANSACTION
   - Set offer.status = "accepted"
   - Set offer.acceptedAt = now
   - Increment job.accepted_count
   - Expire all other student offers
   - If accepted_count == intake: close job, expire pending offers
7. COMMIT
8. Release lock
9. Trigger auto-refill for other jobs if needed
```

**FRONTEND BEHAVIOR:**
- On 200: Show success, update UI with unlocked privacy data
- On 409 OFFER_EXPIRED: Show "offer expired" message, disable action
- On 409 INTAKE_FULL: Show "position filled" message
- On 409 ALREADY_ACCEPTED: Navigate to accepted offer

---

### 4.4 POST /student/offers/:offerId/decline

**DESCRIPTION:**  
Decline an offer.

**AUTH:** Required (student)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| offerId | string | Offer UUID |

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "offer": {
    "id": "offer-uuid",
    "status": "declined",
    "declinedAt": "2024-01-16T09:00:00Z"
  }
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "INVALID_STATE",
  "message": "Offer cannot be declined in current state",
  "currentStatus": "accepted"
}
```

**STATE RULES:**
- Only "offered" offers can be declined
- Transition: offered → declined
- Trigger auto-refill for the job

**FRONTEND BEHAVIOR:**
- On 200: Remove offer from active list
- On 409: Display error, refresh offer state

---

## 5. Review APIs

### 5.1 POST /student/reviews

**DESCRIPTION:**  
Submit a review request (flag a match).

**AUTH:** Required (student)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| matchId | string | Yes | Match/Offer ID being flagged |
| reason | string | Yes | Reason code |
| details | string | No | Additional explanation (max 500 chars) |

**Reason Codes:**
- `SKILLS_MISINTERPRETED`
- `RESUME_CONTEXT_IGNORED`
- `DOMAIN_MISMATCH`
- `LOCATION_LOGIC_INCORRECT`
- `OTHER`

**RESPONSE (201 Created):**

```json
{
  "id": "review-uuid",
  "matchId": "offer-uuid",
  "reason": "SKILLS_MISINTERPRETED",
  "details": "My Python experience was not considered",
  "status": "submitted",
  "createdAt": "2024-01-16T09:00:00Z"
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "REVIEW_EXISTS",
  "message": "A review has already been submitted for this match"
}
```

**STATE RULES:**
- One review per match per student
- Reviews are immutable after submission
- Initial status: submitted

**FRONTEND BEHAVIOR:**
- On 201: Show confirmation, disable flag button for this match
- On 409: Show "already flagged" message

---

### 5.2 GET /student/reviews

**DESCRIPTION:**  
Get all review requests by current student.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "reviews": [
    {
      "id": "review-uuid",
      "matchId": "offer-uuid",
      "reason": "SKILLS_MISINTERPRETED",
      "details": "My Python experience was not considered",
      "status": "under_review",
      "createdAt": "2024-01-16T09:00:00Z",
      "updatedAt": "2024-01-17T10:00:00Z"
    }
  ]
}
```

**STATE RULES:**
- Return all reviews regardless of status
- Status values: submitted, under_review, resolved

**FRONTEND BEHAVIOR:**
- On 200: Display review history with status badges

---

### 5.3 GET /student/reviews/:reviewId

**DESCRIPTION:**  
Get single review details.

**AUTH:** Required (student)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| reviewId | string | Review UUID |

**RESPONSE (200 OK):**

```json
{
  "id": "review-uuid",
  "matchId": "offer-uuid",
  "reason": "SKILLS_MISINTERPRETED",
  "details": "My Python experience was not considered",
  "status": "resolved",
  "resolution": {
    "outcome": "ACKNOWLEDGED",
    "notes": "Skill extraction has been refined based on feedback",
    "resolvedAt": "2024-01-18T10:00:00Z"
  },
  "createdAt": "2024-01-16T09:00:00Z"
}
```

**STATE RULES:**
- Resolution only visible when status = resolved
- Outcome values: ACKNOWLEDGED, REJECTED, NO_ACTION

**FRONTEND BEHAVIOR:**
- On 200: Display full review with resolution if available

---

## 6. Application APIs

### 6.1 GET /student/application/status

**DESCRIPTION:**  
Get current application status and state.

**AUTH:** Required (student)

**RESPONSE (200 OK):**

```json
{
  "status": "submitted",
  "submittedAt": "2024-01-15T10:00:00Z",
  "cooldown": null,
  "withdrawn": false,
  "matchResult": {
    "status": "matched",
    "processedAt": "2024-01-15T12:00:00Z"
  }
}
```

**RESPONSE (200 OK - Cooldown Active):**

```json
{
  "status": "cooldown",
  "submittedAt": null,
  "cooldown": {
    "reason": "WITHDRAWAL",
    "startedAt": "2024-01-10T10:00:00Z",
    "endsAt": "2024-02-09T10:00:00Z",
    "daysRemaining": 24
  },
  "withdrawn": true,
  "matchResult": null
}
```

**STATE RULES:**
- Cooldown period is 30 days (configurable)
- Cooldown triggers: withdrawal, certain rejections

**FRONTEND BEHAVIOR:**
- On 200 with cooldown: Display countdown, disable submission
- On 200 without cooldown: Show current status

---

### 6.2 POST /student/application/withdraw

**DESCRIPTION:**  
Withdraw current application.

**AUTH:** Required (student)

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "status": "withdrawn",
  "withdrawnAt": "2024-01-16T10:00:00Z",
  "cooldown": {
    "reason": "WITHDRAWAL",
    "endsAt": "2024-02-15T10:00:00Z"
  },
  "cancelledOffers": [
    {
      "id": "offer-uuid",
      "status": "withdrawn"
    }
  ]
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "CANNOT_WITHDRAW",
  "message": "Cannot withdraw after accepting an offer"
}
```

**STATE RULES:**

```
Withdrawal Process:
1. Check no accepted offers exist
2. Cancel all pending offers (status → withdrawn)
3. Set application.status = withdrawn
4. Start cooldown period (30 days)
5. Trigger auto-refill for affected jobs
```

**FRONTEND BEHAVIOR:**
- On 200: Show cooldown countdown, disable all actions
- On 409: Display error message

---

## 7. Company APIs

### 7.1 GET /company/profile

**DESCRIPTION:**  
Get current company profile.

**AUTH:** Required (company)

**RESPONSE (200 OK):**

```json
{
  "id": "company-uuid",
  "companyName": "TechCorp",
  "email": "hr@techcorp.com",
  "contactPerson": "Jane Smith",
  "gstNumber": "29ABCDE1234F1Z5",
  "emailVerified": true,
  "status": "active",
  "createdAt": "2024-01-01T10:00:00Z"
}
```

**STATE RULES:**
- Return only authenticated company's data

**FRONTEND BEHAVIOR:**
- On 200: Populate company dashboard

---

### 7.2 PATCH /company/profile

**DESCRIPTION:**  
Update company profile.

**AUTH:** Required (company)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| contactPerson | string | No | Contact person name |

**RESPONSE (200 OK):**

```json
{
  "id": "company-uuid",
  "companyName": "TechCorp",
  "contactPerson": "Jane Smith Updated",
  "status": "active"
}
```

**STATE RULES:**
- Company name and GST are immutable after registration
- Contact person can be updated
- Status transitions: profile-pending → active (on profile completion)

**FRONTEND BEHAVIOR:**
- On 200: Update UI, show success toast

---

## 8. Job APIs

### 8.1 POST /company/jobs

**DESCRIPTION:**  
Create a new job posting.

**AUTH:** Required (company)

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | Job title |
| requiredSkills | string[] | Yes | Required skills (1-10) |
| location | object | Yes | { lat, lng, label } |
| intake | number | Yes | Number of positions (1-100) |
| stipend | number | No | Monthly stipend |
| perks | string | No | Additional perks description |
| originalJD | string | Yes | Full job description text |

**RESPONSE (201 Created):**

```json
{
  "id": "job-uuid",
  "companyId": "company-uuid",
  "title": "Frontend Developer Intern",
  "requiredSkills": ["React", "TypeScript"],
  "location": {
    "lat": 12.9716,
    "lng": 77.5946,
    "label": "Bangalore, Karnataka"
  },
  "intake": 3,
  "stipend": 20000,
  "perks": "Flexible hours, Learning budget",
  "originalJD": "...",
  "status": "draft",
  "createdAt": "2024-01-15T10:00:00Z"
}
```

**STATE RULES:**
- Initial status: draft
- Job remains draft until explicitly submitted

**FRONTEND BEHAVIOR:**
- On 201: Navigate to job status page

---

### 8.2 GET /company/jobs

**DESCRIPTION:**  
Get all jobs for current company.

**AUTH:** Required (company)

**RESPONSE (200 OK):**

```json
{
  "jobs": [
    {
      "id": "job-uuid",
      "title": "Frontend Developer Intern",
      "intake": 3,
      "acceptedCount": 1,
      "pendingOffers": 2,
      "status": "matched",
      "createdAt": "2024-01-15T10:00:00Z"
    }
  ]
}
```

**STATE RULES:**
- Return all jobs regardless of status
- Include counts for dashboard display

**FRONTEND BEHAVIOR:**
- On 200: Display job list with status indicators

---

### 8.3 GET /company/jobs/:jobId

**DESCRIPTION:**  
Get single job details.

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**RESPONSE (200 OK):**

```json
{
  "id": "job-uuid",
  "companyId": "company-uuid",
  "title": "Frontend Developer Intern",
  "requiredSkills": ["React", "TypeScript"],
  "location": {
    "lat": 12.9716,
    "lng": 77.5946,
    "label": "Bangalore, Karnataka"
  },
  "intake": 3,
  "acceptedCount": 1,
  "pendingOffers": 2,
  "stipend": 20000,
  "perks": "Flexible hours",
  "originalJD": "...",
  "status": "matched",
  "createdAt": "2024-01-15T10:00:00Z",
  "processedAt": "2024-01-15T12:00:00Z"
}
```

**STATE RULES:**
- Company can only access own jobs

**FRONTEND BEHAVIOR:**
- On 200: Display full job details

---

### 8.4 POST /company/jobs/:jobId/submit

**DESCRIPTION:**  
Submit job for processing (trigger matching).

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "job": {
    "id": "job-uuid",
    "status": "processing"
  }
}
```

**RESPONSE (409 Conflict):**

```json
{
  "error": "INVALID_STATE",
  "message": "Job is not in draft state"
}
```

**STATE RULES:**
- Only draft jobs can be submitted
- Transition: draft → processing
- Triggers async matching job

**FRONTEND BEHAVIOR:**
- On 200: Navigate to job status, show "processing" indicator
- On 409: Display error

---

### 8.5 POST /company/jobs/:jobId/close

**DESCRIPTION:**  
Manually close a job posting.

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**REQUEST BODY:** None

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "job": {
    "id": "job-uuid",
    "status": "closed",
    "closedAt": "2024-01-20T10:00:00Z"
  },
  "expiredOffers": 2
}
```

**STATE RULES:**
- Expire all pending offers
- Set status = closed
- No new offers can be created
- Accepted offers remain valid

**FRONTEND BEHAVIOR:**
- On 200: Update job status in UI

---

## 9. Matching APIs

### 9.1 POST /company/jobs/:jobId/match

**DESCRIPTION:**  
Trigger matching for a job (system action).

**AUTH:** Required (company) OR system

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**RESPONSE (200 OK):**

```json
{
  "success": true,
  "job": {
    "id": "job-uuid",
    "status": "matched"
  },
  "matchesCreated": 15
}
```

**STATE RULES:**
- Job must be in "processing" status
- Backend runs matching algorithm
- Creates ranked list of match proposals
- Transition: processing → matched

**FRONTEND BEHAVIOR:**
- On 200: Refresh match list

---

### 9.2 GET /company/jobs/:jobId/matches

**DESCRIPTION:**  
Get all match proposals for a job.

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**RESPONSE (200 OK):**

```json
{
  "matches": [
    {
      "id": "match-uuid",
      "studentId": "student-uuid",
      "studentName": "John D.",
      "skills": ["React", "TypeScript", "Node.js"],
      "score": 87,
      "explanation": [
        "Strong React and TypeScript match",
        "Location within preferred distance"
      ],
      "status": "proposed",
      "privacy": {
        "fullNameVisible": false,
        "contactVisible": false,
        "resumeVisible": false
      }
    }
  ],
  "summary": {
    "total": 15,
    "proposed": 10,
    "approved": 3,
    "rejected": 2
  }
}
```

**STATE RULES:**
- Company sees partial student info before approval
- Full info only after mutual acceptance
- Matches are system-ranked (order is meaningful)

**FRONTEND BEHAVIOR:**
- On 200: Display ranked match list

---

### 9.3 POST /company/matches/:matchId/action

**DESCRIPTION:**  
Approve or reject a match proposal.

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| matchId | string | Match UUID |

**REQUEST BODY:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | "approve" or "reject" |

**RESPONSE (200 OK - Approve):**

```json
{
  "success": true,
  "match": {
    "id": "match-uuid",
    "status": "approved"
  },
  "offerCreated": {
    "id": "offer-uuid",
    "expiresAt": "2024-01-20T10:00:00Z"
  }
}
```

**RESPONSE (200 OK - Reject):**

```json
{
  "success": true,
  "match": {
    "id": "match-uuid",
    "status": "rejected"
  }
}
```

**STATE RULES:**
- Approve → creates offer for student (if intake allows)
- Reject → student not notified
- Only "proposed" matches can be actioned

**FRONTEND BEHAVIOR:**
- On 200: Update match status in list

---

### 9.4 GET /company/jobs/:jobId/summary

**DESCRIPTION:**  
Get summary statistics for job matching.

**AUTH:** Required (company)

**PATH PARAMS:**

| Param | Type | Description |
|-------|------|-------------|
| jobId | string | Job UUID |

**RESPONSE (200 OK):**

```json
{
  "jobId": "job-uuid",
  "intake": 3,
  "acceptedCount": 1,
  "pendingOffers": 2,
  "proposedMatches": 10,
  "approvedMatches": 5,
  "rejectedMatches": 2,
  "status": "matched",
  "canCreateMoreOffers": true
}
```

**STATE RULES:**
- canCreateMoreOffers = acceptedCount + pendingOffers < intake

**FRONTEND BEHAVIOR:**
- On 200: Display dashboard summary

---

## 10. Error Codes Reference

### 10.1 HTTP Status Codes

| Code | Meaning | Common Scenarios |
|------|---------|------------------|
| 200 | Success | Request completed |
| 201 | Created | Resource created |
| 400 | Bad Request | Validation error |
| 401 | Unauthorized | Invalid/expired token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | State conflict |
| 413 | Payload Too Large | File too big |
| 429 | Too Many Requests | Rate limited |
| 500 | Server Error | Internal error |

### 10.2 Error Code Reference

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| VALIDATION_ERROR | 400 | Input validation failed |
| INVALID_OTP | 400 | OTP incorrect or expired |
| EMPTY_SKILLS | 400 | No skills provided |
| INVALID_FILE | 400 | Wrong file format |
| INVALID_CREDENTIALS | 401 | Wrong email/password |
| UNAUTHORIZED | 401 | Token invalid/expired |
| INVALID_REFRESH_TOKEN | 401 | Refresh token invalid |
| ACCESS_DENIED | 403 | Permission denied |
| RESUME_NOT_FOUND | 404 | Resume doesn't exist |
| EMAIL_EXISTS | 409 | Email already registered |
| PROFILE_LOCKED | 409 | Can't modify after submission |
| OFFER_EXPIRED | 409 | Offer past deadline |
| INTAKE_FULL | 409 | Position filled |
| ALREADY_ACCEPTED | 409 | Already has accepted offer |
| REVIEW_EXISTS | 409 | Already flagged this match |
| INVALID_STATE | 409 | Invalid state transition |
| CANNOT_WITHDRAW | 409 | Has accepted offer |
| FILE_TOO_LARGE | 413 | File exceeds limit |
| RATE_LIMITED | 429 | Too many requests |

### 10.3 Standard Error Response Format

```json
{
  "error": "ERROR_CODE",
  "message": "Human readable message",
  "field": "fieldName",
  "details": {}
}
```

---

## Appendix: System Constraints (Backend Must Enforce)

### A.1 Atomic Intake Locking

```
Every offer acceptance MUST:
1. Acquire exclusive lock on job
2. Verify accepted_count < intake
3. Increment accepted_count atomically
4. Release lock

Failure mode: If lock contention, retry with backoff
```

### A.2 Offer State Machine

```
Valid: offered → accepted | declined | expired | withdrawn
Invalid: any other transition

Terminal states: accepted, declined, expired, withdrawn
```

### A.3 Grace Period Expiry

```
System MUST:
1. Set expiresAt on offer creation
2. Check expiry BEFORE any accept
3. Run scheduled job to expire offers
4. Return 409 if expired at accept time
```

### A.4 Single Accept Enforcement

```
Before accepting:
1. Check student has no other accepted offers
2. If exists: return 409 ALREADY_ACCEPTED
3. On success: expire all other offers for student
```

### A.5 Auto-Refill Queue

```
Trigger on: decline | expire | withdraw
Check: accepted_count < intake
Action: Issue offer to next ranked candidate
Guarantee: Automatic, deterministic, idempotent
```

### A.6 Resume Version Binding

```
Every match MUST store:
- resumeId
- resumeVersion

This link is IMMUTABLE after match creation.
```

### A.7 Cooldown Enforcement

```
After withdrawal:
- cooldownEndsAt = now + 30 days
- Block all submissions until cooldown ends
- Return 409 with countdown on submit attempts
```

---

**END OF DOCUMENT B**
