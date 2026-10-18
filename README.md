# Secure Exam Question Paper Access System

## About the Project

The Secure Exam Question Paper Access System is a web application developed to manage examination question papers securely. It allows setters to upload question papers, approvers to approve them, and invigilators to access them during the permitted exam time.

The system uses encryption to protect question papers, a threshold-based approval process to control access, and audit logs to keep track of important activities.

## How It Works

1. **User Login:** Users log in using their registered accounts. New users need an administrator to assign them a role before they can access the system.
2. **Upload Question Paper:** A setter uploads a question paper. The file is encrypted before being stored.
3. **Set Approvals:** The setter selects the required approvers and specifies how many approvals are needed to unlock the paper.
4. **Approve the Paper:** The selected approvers log in and approve the paper assigned to them.
5. **Unlock the Paper:** Once the required approvals are received and the exam time conditions are satisfied, an authorized invigilator can unlock the paper.
6. **Audit Logs:** Important activities are recorded in an audit log. The system can verify the log's hash chain to detect modifications.

## Features

- Encrypted storage of question papers
- Role-based login and access control
- Configurable approval threshold
- Shamir's Secret Sharing for splitting the encryption key
- Time-based restrictions on unlocking question papers
- Admin panel for assigning user roles
- Audit logs with hash-chain verification
- Audit tampering simulation and restoration for demonstration, when enabled
- Access-token and refresh-token authentication
- Input validation and login rate limiting

## Algorithms and Concepts Used

| Algorithm / Concept | Purpose |
|---|---|
| **AES-256-GCM** | Encrypts question papers and verifies the integrity of encrypted data |
| **Shamir's Secret Sharing** | Splits the encryption key into shares and reconstructs it when the required threshold is met |
| **Lagrange Interpolation** | Reconstructs the secret from the required number of shares |
| **SHA-256 Hashing** | Links audit entries together to form a hash chain |
| **HMAC-SHA-256** | Provides keyed integrity protection for supported audit entries |
| **JWT Authentication** | Authenticates API requests using access tokens |
| **Refresh Token Rotation** | Issues replacement refresh tokens and helps detect reuse of older tokens |
| **Role-Based Access Control (RBAC)** | Restricts operations according to each user's role |
| **bcrypt** | Hashes user passwords before storing them |

## User Roles

| Role | Responsibilities |
|---|---|
| **Admin** | Manages users and assigns roles |
| **Setter** | Uploads question papers and selects approvers and the approval threshold |
| **Approver** | Reviews and approves assigned question papers |
| **Invigilator** | Unlocks and accesses papers when the approval and exam-time requirements are satisfied |
| **Pending User** | A newly registered user waiting for an administrator to assign a role |

Only users with an `@iiitkottayam.ac.in` email address can register. Newly registered accounts remain pending until the administrator assigns an eligible role.

## Project Structure

```text
Secure-Exam-Question-Paper-Access-System/
├── backend/
│   ├── controllers/    # Authentication, paper and audit logic
│   ├── routes/         # API routes
│   ├── middleware/     # Authentication and authorization
│   ├── models/         # MongoDB models
│   ├── scripts/        # Admin and test-user seeding
│   └── server.js       # Backend entry point
├── frontend/
│   ├── index.html      # Web interface
│   ├── css/            # Stylesheets
│   └── js/             # Frontend logic and API calls
└── crypto/             # Cryptographic implementation and tests
```

## Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js, Express.js
- **Database:** MongoDB
- **Security:** AES-256-GCM, Shamir's Secret Sharing, SHA-256, HMAC-SHA-256, JWT and bcrypt

## Running the Project

### 1. Configure the backend

```bash
cd backend
```

Copy `.env.example` to `.env` and configure the MongoDB connection, authentication secrets, cryptographic keys, and administrator credentials.

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create the administrator account

```bash
npm run seed:admin
```

### 4. Start the server

```bash
npm run dev
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

The backend serves the frontend, so the application can be accessed through the same address.

## Testing

The project includes tests for cryptographic operations, authentication, user management, and the question-paper workflow.

Run the tests from the project root:

```bash
node crypto/test.js
node backend/test-units.js
node backend/test-auth-admin.js
node backend/test-flow.js
```

Some tests may require the backend and a configured MongoDB database.

## Note

This project was developed as part of a course project to demonstrate encryption, access control, threshold-based approvals, and audit-log verification in a question-paper management system.
