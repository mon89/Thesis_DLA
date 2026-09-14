 (cd "$(git rev-parse --show-toplevel)" && printf '%s' 'diff --git a/README.md b/README.md
index 44e886b63431e9ac38d6e851f47133ba2656169c..1d23ee2e447fb642e0beffa5ef79dfaadd8ff81c 100644
--- a/README.md
+++ b/README.md
@@ -8,51 +8,51 @@ This repository contains the implementation and research for a master thesis pro
 
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
-- Each device generates a unique **Ed25519 key pair**
+- Each Android device generates a unique **P-256 EC key pair** in Android Keystore (StrongBox when available, otherwise TEE)
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
@@ -79,51 +79,51 @@ New device (not in database) signs in
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
-2. **Client Signing**: Device signs challenge using **DBK Private Key** → Ed25519 signature
+2. **Client Signing**: Device signs the challenge using **ECDSA-SHA256** with its DBK private key and sends the signature in IEEE P1363 (`r || s`) format
 3. **Server Verification**: 
    - Existing devices: Verify against **STORED** `dbkPublicKey` from database
    - New devices: Verify against key submitted at `/challenge` time (session-stored, never from request body)
    - Protection: Server is always authoritative; client cannot influence which key is used
 
 #### Device Detection Logic (in `/verify` endpoint)
 ```typescript
 const flow = trustedCount === 0 && !existing                           ? '\''BOOTSTRAP'\''
            : existing?.status === '\''TRUSTED'\''                           ? '\''TRUSTED_DEVICE'\''
            : !existing && trustedCount >= 1                           ? '\''NEW_DEVICE'\''
            : existing?.status === '\''PENDING'\''                           ? '\''PENDING'\''
            : existing?.status === '\''REJECTED'\'' || '\''REVOKED'\''             ? '\''BLOCKED'\''
            : '\''UNKNOWN'\'';
 ```
 
 The server determines device status by:
 1. Computing `deviceId` from submitted DBK Public Key
 2. Looking up device in database: `DeviceProfile.findOne({ userId, deviceId })`
 3. Checking trusted device count: `DeviceProfile.countDocuments({ userId, status: '\''TRUSTED'\'' })`
 4. Evaluating combination → determines enrollment flow
 
 ### Key Enrollment Signals
 
 When a device is enrolled, the system captures:
 - **userAgent** - Browser/app identifier
@@ -132,181 +132,229 @@ When a device is enrolled, the system captures:
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
-├── kotlin/                         # Android app implementation
-│── typescript/                     # Web frontend implementation
+├── app/                            # Kotlin/Jetpack Compose Android application
+├── public/                         # Small static browser landing page
 └── docs/                          # Documentation and research materials
 ```
 
 ## Getting Started
 
 ### Prerequisites
 
-- **TypeScript/Node.js** (for web components)
-  - Node.js 16.x or higher
-  - npm or yarn package manager
+- A VPS or other publicly reachable Linux server
+- A real domain name whose DNS record points to that server
+- A valid TLS/SSL certificate for the domain (for example, from Let'\''s Encrypt)
+- A reverse proxy such as nginx to terminate HTTPS and forward requests to Node.js
+- Node.js, npm, and MongoDB
+- JDK 11+, Android Studio, and the Android SDK
+- A physical Android device with a screen lock and passkey provider configured; a physical device is recommended for authenticator and hardware-backed-key demonstrations
 
-- **Kotlin/Java** (for mobile app)
-  - Java Development Kit (JDK) 11 or higher
-  - Android SDK
-  - Android Studio or IntelliJ IDEA
-
-- **Database**
-  - MongoDB (for device profiles, approval requests, user accounts)
+> **Why a real HTTPS domain is required:** WebAuthn credentials are scoped to a relying-party ID and origin. Android Credential Manager also validates the relationship between the website and the signed Android application through Digital Asset Links. A plain VPS IP address or an unrelated HTTP origin is not equivalent to this prototype'\''s deployed relying party.
 
 ### Installation
 
 1. Clone the repository:
 ```bash
 git clone https://github.com/mon89/Thesis_DLA.git
 cd Thesis_DLA
 ```
 
-2. Set up environment variables (`.env`):
+2. Install and configure MongoDB on the VPS, then create `backend/.env`. Replace the example domain and secrets with your deployment values:
 ```bash
 MONGODB_URI=mongodb://localhost:27017/thesis-dla
-SESSION_SECRET=your-session-secret
-RP_ID=localhost
-ORIGIN=http://localhost:3000
+SESSION_SECRET=generate-a-long-random-secret
+RP_ID=auth.example.com
+ORIGIN=https://auth.example.com
+RP_NAME=DLA Research Prototype
+ANDROID_ORIGIN=android:apk-key-hash:YOUR_BASE64URL_CERT_HASH
 PORT=3000
+NODE_ENV=production
+```
+
+`RP_ID` is the domain only (no scheme or path), while `ORIGIN` is the complete HTTPS origin. Obtain the SHA-256 fingerprint of the certificate used to sign the Android build, then convert it to the required Android origin:
+
+```bash
+cd backend
+npx ts-node scripts/compute-android-hash.ts "AA:BB:CC:..."
 ```
 
-3. Set up TypeScript/Node.js backend:
+3. Configure the Android/domain association before building the app:
+
+- Replace the domain in `app/src/main/res/values/strings.xml`.
+- Replace the package name and signing-certificate SHA-256 fingerprint in `backend/public/.well-known/assetlinks.json`.
+- If you change the application ID, keep the Android manifest, Gradle configuration, and `assetlinks.json` package name consistent.
+- Update `APIClient.BASE_URL` in `app/src/main/java/com/example/dlaauth/service/APIClient.kt` to the HTTPS origin of your VPS.
+- Serve `https://auth.example.com/.well-known/assetlinks.json` without redirects and with an `application/json` content type.
+
+4. Install, build, and run the backend from the **backend directory**:
 ```bash
+cd backend
 npm install
 npm run build
 npm start
 ```
 
-4. Set up Kotlin/Android project:
+For development on the VPS, use `npm run dev` instead. Keep Node.js behind the HTTPS reverse proxy. The proxy must preserve the host, client IP, and HTTPS-forwarding headers; the server already trusts one proxy hop for secure session cookies.
+
+5. Verify the public deployment before opening Android Studio:
 ```bash
-cd kotlin
-./gradlew build
-# Or open in Android Studio and run
+curl https://auth.example.com/api/health
+curl https://auth.example.com/.well-known/assetlinks.json
 ```
 
-### Running the Application
+6. Open the repository root in Android Studio, allow Gradle sync to finish, select the correctly signed build variant, connect the Android device, and press **Run**. Use the app to register the first passkey/device, sign in again as a trusted device, and demonstrate approval of a second Android device.
 
-**Web Application:**
-```bash
-npm run dev
-```
+### Demonstration Notes
 
-**Android Application:**
-```bash
-./gradlew assembleDebug
-# Or open the project in Android Studio and run
-```
+- The certificate fingerprint in `assetlinks.json` must match the APK that Android Studio installs. A debug build normally uses the developer'\''s debug keystore; a release build uses the release signing certificate.
+- Passkey registration and authentication will fail if `RP_ID`, `ORIGIN`, `ANDROID_ORIGIN`, `assetlinks.json`, the Android package, or the signing certificate do not agree.
+- The first device for a user follows the bootstrap flow and becomes trusted. A second device remains pending until the first device approves it and the second device completes finalization.
+- StrongBox is hardware-dependent. On devices without StrongBox, the prototype falls back to TEE-backed Android Keystore.
 
 ### Testing Device Flows
 
-Run integration tests to verify enrollment flows:
+The backend contains a full-flow script and a controlled detection simulation. Run them only against a disposable research database because the flow script resets collections:
 ```bash
-npm run test:flow
-npm run test:detection  # Attack simulation tests
+cd backend
+npm test
+ITERATIONS=30 npx ts-node scripts/sim_detection.ts
 ```
 
+These scripts are research harnesses, not production security certification. Review their target URL and protocol assumptions before running them against a deployed VPS.
+
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
   - `{ flow: '\''BOOTSTRAP'\'', status: '\''TRUSTED'\'', authComplete: true }`
   - `{ flow: '\''TRUSTED_DEVICE'\'', status: '\''TRUSTED'\'', authComplete: true }`
   - `{ flow: '\''NEW_DEVICE'\'', status: '\''PENDING'\'', approvalRequired: true }`
   - `{ flow: '\''BLOCKED'\'', status: '\''REJECTED|REVOKED'\'' }`
 
 ### 3. POST `/api/device/approval/decide`
 Trusted device approves/denies new device enrollment
 - **Auth**: Requires full authentication + trusted device
 - **Body**: `{ requestId, decision: '\''APPROVED'\''|'\''DENIED'\'', signature }`
-- **Signature**: Ed25519 signature over approval payload
+- **Signature**: ECDSA-SHA256 signature over the canonical approval payload
 
 ### 4. POST `/api/device/finalize`
 New device completes enrollment after approval
 - **Auth**: Requires passkey verification
 - **Body**: `{ requestId, loginAttemptId, signature }`
 - **Response**: `{ flow: '\''NEWLY_APPROVED'\'', status: '\''TRUSTED'\'', authComplete: true }`
 
 ### 5. GET `/api/device/list`
 List all enrolled devices for current user
 - **Auth**: Requires full authentication
 - **Response**: Array of device records with status, signals, and metadata
 
 ### 6. GET `/api/device/approval/pending`
 Get pending enrollment approval requests for trusted device
 - **Auth**: Requires full authentication
 - **Response**: Array of pending approval requests waiting for this device'\''s decision
 
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
 
-As this is a master thesis project, external contributions are limited. For inquiries or collaboration opportunities, please contact the repository owner.
+This thesis research prototype is shared so that students and researchers can study and improve the risks around synchronized passkeys and multi-device authentication. Contributions that reproduce an issue, add a test, clarify an assumption, or evaluate another threat model are welcome.
+
+When contributing:
+
+1. Describe the attacker capability and expected security property.
+2. Use a disposable MongoDB database and test account.
+3. Never commit `.env` files, private keys, session secrets, VPS credentials, or release keystores.
+4. Add automated tests or reproducible experiment steps where possible.
+5. Report latency and detection results as controlled experimental results, not universal guarantees.
+
+## Future Directions
+
+### High priority: make bootstrap enrollment concurrency-safe
+
+The current bootstrap rule is conceptually simple: when a user has no trusted device, the first valid device becomes `TRUSTED`. The implementation checks the trusted-device count, inserts the candidate, checks the count again, and demotes a device if it detects a race.
+
+That mitigation is incomplete. If two different devices bootstrap the same account at nearly the same time, both requests can initially see zero trusted devices and both can insert a trusted profile. In an unlucky interleaving, both requests may then see more than one trusted profile and each may demote itself to `PENDING`. The account could be left with no trusted device able to approve either request.
+
+This is a useful next contribution for a junior developer because it has a clear invariant and can be improved incrementally:
+
+> For each user, bootstrap must elect exactly one first trusted device, even when multiple requests arrive concurrently.
+
+Suggested implementation path:
+
+1. First write an integration test that sends two bootstrap attempts concurrently for one user with two different DBKs.
+2. Assert that exactly one device finishes as `TRUSTED`; every other candidate must be `PENDING` and must reference the elected trusted approver.
+3. Move bootstrap election into an atomic database design, such as a MongoDB transaction with a per-user enrollment/lock document or another conditional write that can have only one winner.
+4. Do not rely only on the existing unique `(userId, deviceId)` index: it prevents duplicate records for the same device, but it does not enforce one bootstrap winner across different device IDs.
+5. Add retry and rollback handling, then repeat the test many times to make race failures observable.
+6. Record the concurrency model and remaining failure cases in the research documentation.
+
+Other useful future work includes a persistent session store for multi-instance experiments, broader adversarial scenarios, Android unit tests for signature conversion and state transitions, explicit device revocation UI/API support, and evaluation of how passkey synchronization changes the assumed boundary between user authentication and device possession.
 
 ## Author
 
 - **mon89** - Master Thesis Project
 
 ## License
 
 [Specify your license - e.g., MIT, Apache 2.0]
 
 ## Contact
 
 For questions about this research or implementation, please open an issue or contact the repository owner.
 
 ## References
 
 - [FIDO2 Specification](https://fidoalliance.org/fido2/)
 - [WebAuthn Standard](https://www.w3.org/TR/webauthn-2/)
-- [Ed25519 Cryptography](https://ed25519.cr.yp.to/)
+- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
 - [Android Biometric API](https://developer.android.com/training/sign-in/biometric-auth)
 - [MongoDB Device Profile Schema](./backend/models/DeviceProfile.ts)
' | git apply --3way)
