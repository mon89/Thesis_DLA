# Passkey Authenticator

A master thesis project implementing a modern passkey authentication system using TypeScript and Kotlin with advanced device enrollment and verification mechanisms.

## Overview

This repository contains the implementation and research for a master thesis project focused on passkey-based authentication. Passkeys provide a passwordless, phishing-resistant authentication method that leverages cryptographic keys instead of traditional passwords. This project explores the integration of passkey authentication across web and mobile platforms, with a sophisticated device enrollment and trust management system.

## Technology Stack

- **TypeScript** (58.2%) - Web-based authentication interface and API implementation
- **Kotlin** (41.6%) - Android mobile app and backend services
- **Other** (0.2%) - Configuration and utility files

## Key Features

- **Passwordless Authentication** - Secure authentication without passwords
- **Cross-Platform Support** - Web application (TypeScript) and Android app (Kotlin)
- **FIDO2/WebAuthn Compliance** - Standards-based passkey implementation
- **Device-Based Key Authentication (DBK)** - Cryptographic key per device for enrollment detection
- **Smart Device Detection** - Automatically detects new vs. enrolled devices using DBK signatures
- **Multi-Device Trust Management** - Approve/deny new device enrollment with trusted devices
- **User-Friendly Experience** - Seamless authentication flow with device enrollment workflows
- **Security-First Design** - Cryptographic key management and secure storage

## Architecture

### Device Enrollment & Detection System

The core innovation is the **Device-Based Key (DBK)** system that detects whether a device is new or already enrolled:

#### Device Identification (DBK Public Key)
- Each device generates a unique **Ed25519 key pair**
- A `deviceId` is computed as `SHA-256(DBK Public Key)` - deterministic and unique per device
- The `dbkPublicKey` is stored in the server database when a device is first enrolled

#### Device Status Tracking
The system maintains device profiles with four states:

| Status | Meaning | Flow |
|--------|---------|------|
| **TRUSTED** | Device is fully approved and can authenticate | Direct login, approves new devices |
| **PENDING** | New device awaiting approval from a trusted device | Requires approval before login |
| **REJECTED** | Device was denied approval | Cannot authenticate or enroll |
| **REVOKED** | Device was previously trusted, now disabled | Blocked from future authentication |

#### Enrollment Flows

**1. Bootstrap Flow (First Device)**
```
User authenticates via Passkey
   ↓
POST /api/device/challenge (submit DBK Public Key)
   ↓
POST /api/device/verify (sign challenge with DBK Private Key)
   ↓
Server checks: trustedCount == 0 && device not in database
   ↓
✓ Device enrolled as TRUSTED
```

**2. Trusted Device Authentication**
```
Device already in database with status = TRUSTED
   ↓
POST /api/device/challenge (submit DBK Public Key)
   ↓
POST /api/device/verify (sign challenge with DBK Private Key)
   ↓
Server verifies signature against STORED dbkPublicKey
   ↓
✓ Authentication successful
```

**3. New Device Enrollment (Requires Approval)**
```
New device (not in database) signs in
   ↓
POST /api/device/challenge (submit DBK Public Key)
   ↓
POST /api/device/verify (sign challenge with DBK Private Key)
   ↓
Server checks: trustedCount >= 1 && device not in database
   ↓
Device created with status = PENDING
   ↓
Approval request sent to a TRUSTED device
   ↓
POST /api/device/approval/decide (trusted device approves/denies with DBK signature)
   ↓
If APPROVED: Device waits for finalization
   ↓
POST /api/device/challenge (fresh challenge)
   ↓
POST /api/device/finalize (new device proves ownership again)
   ↓
✓ Device promoted to TRUSTED
```

### Cryptographic Details

#### Challenge-Response Verification
1. **Challenge Generation**: Server generates random `challenge`
2. **Client Signing**: Device signs challenge using **DBK Private Key** → Ed25519 signature
3. **Server Verification**: 
   - Existing devices: Verify against **STORED** `dbkPublicKey` from database
   - New devices: Verify against key submitted at `/challenge` time (session-stored, never from request body)
   - Protection: Server is always authoritative; client cannot influence which key is used

#### Device Detection Logic (in `/verify` endpoint)
```typescript
const flow = trustedCount === 0 && !existing                           ? 'BOOTSTRAP'
           : existing?.status === 'TRUSTED'                           ? 'TRUSTED_DEVICE'
           : !existing && trustedCount >= 1                           ? 'NEW_DEVICE'
           : existing?.status === 'PENDING'                           ? 'PENDING'
           : existing?.status === 'REJECTED' || 'REVOKED'             ? 'BLOCKED'
           : 'UNKNOWN';
```

The server determines device status by:
1. Computing `deviceId` from submitted DBK Public Key
2. Looking up device in database: `DeviceProfile.findOne({ userId, deviceId })`
3. Checking trusted device count: `DeviceProfile.countDocuments({ userId, status: 'TRUSTED' })`
4. Evaluating combination → determines enrollment flow

### Key Enrollment Signals

When a device is enrolled, the system captures:
- **userAgent** - Browser/app identifier
- **platform** - Operating system
- **timezone** - Geographic/temporal indicator
- **ip** - Source IP address
- **enrolledAt** - Enrollment timestamp

These signals help detect anomalies and potential device spoofing.

## Project Structure

```
Thesis_DLA/
├── backend/
│   ├── routes/
│   │   ├── device.ts              # Device enrollment/verification endpoints
│   │   ├── webauthn.ts            # Passkey registration/authentication
│   │   └── api.ts                 # General API endpoints
│   ├── models/
│   │   ├── DeviceProfile.ts       # Device record schema
│   │   ├── ApprovalRequest.ts     # Enrollment approval requests
│   │   └── User.ts                # User account schema
│   ├── utils/
│   │   ├── crypto.ts              # DBK signing/verification, device ID computation
│   │   └── logger.ts              # Security audit logging
│   ├── scripts/
│   │   ├── test-flow.ts           # Integration tests
│   │   └── sim_detection.ts       # Attack simulation tests
│   └── server.ts                  # Express server setup
├── kotlin/                         # Android app implementation
│── typescript/                     # Web frontend implementation
└── docs/                          # Documentation and research materials
```

## Getting Started

### Prerequisites

- **TypeScript/Node.js** (for web components)
  - Node.js 16.x or higher
  - npm or yarn package manager

- **Kotlin/Java** (for mobile app)
  - Java Development Kit (JDK) 11 or higher
  - Android SDK
  - Android Studio or IntelliJ IDEA

- **Database**
  - MongoDB (for device profiles, approval requests, user accounts)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/mon89/Thesis_DLA.git
cd Thesis_DLA
```

2. Set up environment variables (`.env`):
```bash
MONGODB_URI=mongodb://localhost:27017/thesis-dla
SESSION_SECRET=your-session-secret
RP_ID=localhost
ORIGIN=http://localhost:3000
PORT=3000
```

3. Set up TypeScript/Node.js backend:
```bash
npm install
npm run build
npm start
```

4. Set up Kotlin/Android project:
```bash
cd kotlin
./gradlew build
# Or open in Android Studio and run
```

### Running the Application

**Web Application:**
```bash
npm run dev
```

**Android Application:**
```bash
./gradlew assembleDebug
# Or open the project in Android Studio and run
```

### Testing Device Flows

Run integration tests to verify enrollment flows:
```bash
npm run test:flow
npm run test:detection  # Attack simulation tests
```

## API Endpoints (Device Management)

### 1. POST `/api/device/challenge`
Submit DBK Public Key and receive challenge
- **Auth**: Requires passkey verification
- **Body**: `{ dbkPublicKey: JWK }`
- **Response**: `{ challenge, trustedDeviceCount, isBootstrap }`

### 2. POST `/api/device/verify`
Submit DBK signature over challenge
- **Auth**: Requires passkey verification
- **Body**: `{ signature, signals?, clientMetrics? }`
- **Response**: Depends on flow:
  - `{ flow: 'BOOTSTRAP', status: 'TRUSTED', authComplete: true }`
  - `{ flow: 'TRUSTED_DEVICE', status: 'TRUSTED', authComplete: true }`
  - `{ flow: 'NEW_DEVICE', status: 'PENDING', approvalRequired: true }`
  - `{ flow: 'BLOCKED', status: 'REJECTED|REVOKED' }`

### 3. POST `/api/device/approval/decide`
Trusted device approves/denies new device enrollment
- **Auth**: Requires full authentication + trusted device
- **Body**: `{ requestId, decision: 'APPROVED'|'DENIED', signature }`
- **Signature**: Ed25519 signature over approval payload

### 4. POST `/api/device/finalize`
New device completes enrollment after approval
- **Auth**: Requires passkey verification
- **Body**: `{ requestId, loginAttemptId, signature }`
- **Response**: `{ flow: 'NEWLY_APPROVED', status: 'TRUSTED', authComplete: true }`

### 5. GET `/api/device/list`
List all enrolled devices for current user
- **Auth**: Requires full authentication
- **Response**: Array of device records with status, signals, and metadata

### 6. GET `/api/device/approval/pending`
Get pending enrollment approval requests for trusted device
- **Auth**: Requires full authentication
- **Response**: Array of pending approval requests waiting for this device's decision

## Security Considerations

- **Private keys never leave the device** - Only public keys and signatures are transmitted
- **Server-authoritative verification** - Server always uses stored keys for verification
- **Replay attack prevention** - Challenges consumed after use
- **Device binding** - DBK Public Key hash uniquely identifies device
- **Approval signatures** - Device approval decisions are cryptographically signed
- **All communication uses TLS/HTTPS encryption**
- **Audit logging** - All device operations logged for forensics

## Research & Documentation

This project is part of a master thesis exploring device-based authentication, multi-device trust models, and automated device enrollment verification. Key research areas include:

- Cryptographic device binding mechanisms
- Attack detection and mitigation strategies
- User experience in multi-device enrollment
- Trust delegation patterns
- Scalability of device management

## Contributing

As this is a master thesis project, external contributions are limited. For inquiries or collaboration opportunities, please contact the repository owner.

## Author

- **mon89** - Master Thesis Project

## License

[Specify your license - e.g., MIT, Apache 2.0]

## Contact

For questions about this research or implementation, please open an issue or contact the repository owner.

## References

- [FIDO2 Specification](https://fidoalliance.org/fido2/)
- [WebAuthn Standard](https://www.w3.org/TR/webauthn-2/)
- [Ed25519 Cryptography](https://ed25519.cr.yp.to/)
- [Android Biometric API](https://developer.android.com/training/sign-in/biometric-auth)
- [MongoDB Device Profile Schema](./backend/models/DeviceProfile.ts)
