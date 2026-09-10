# Passkey Authenticator

A master thesis project implementing a modern passkey authentication system using TypeScript and Kotlin.

## Overview

This repository contains the implementation and research for a master thesis project focused on passkey-based authentication. Passkeys provide a passwordless, phishing-resistant authentication method that leverages cryptographic keys instead of traditional passwords. This project explores the integration of passkey authentication across web and mobile platforms.

## Technology Stack

- **TypeScript** (58.2%) - Web-based authentication interface and API implementation
- **Kotlin** (41.6%) - Android mobile app and backend services
- **Other** (0.2%) - Configuration and utility files

## Key Features

- **Passwordless Authentication** - Secure authentication without passwords
- **Cross-Platform Support** - Web application (TypeScript) and Android app (Kotlin)
- **FIDO2/WebAuthn Compliance** - Standards-based passkey implementation
- **User-Friendly Experience** - Seamless authentication flow
- **Security-First Design** - Cryptographic key management and secure storage

## Project Structure

```
Thesis_DLA/
├── typescript/          # Web application and authentication APIs
├── kotlin/             # Android application and backend services
└── docs/               # Documentation and research materials
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

### Installation

1. Clone the repository:
```bash
git clone https://github.com/mon89/Thesis_DLA.git
cd Thesis_DLA
```

2. Set up TypeScript project:
```bash
cd typescript
npm install
npm run build
```

3. Set up Kotlin/Android project:
```bash
cd kotlin
./gradlew build
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

## Architecture

### Web Component (TypeScript)
- Authentication API endpoints
- WebAuthn credential management
- User registration and login flows
- Session management

### Mobile Component (Kotlin)
- Android passkey authenticator
- Secure credential storage
- Biometric integration
- Push notification support

## Usage

[Add specific instructions for users on how to register and authenticate]

## Research & Documentation

This project is part of a master thesis exploring passkey authentication mechanisms. For detailed research findings, threat analysis, and methodology, refer to the thesis documentation.

## Testing

[Add instructions for running tests]

## Security Considerations

- Private keys are never transmitted to the server
- Credentials are stored securely using device-specific storage
- Biometric verification is used where available
- All communication uses TLS/HTTPS encryption

## Contributing

As this is a master thesis project, contributions are limited. For inquiries or collaboration opportunities, please contact the repository owner.

## Author

- **mon89** - Master Thesis Project

## License

[Specify your license - e.g., MIT, Apache 2.0]

## Contact

For questions about this research or implementation, please open an issue or contact the repository owner.

## References

- [FIDO2 Specification](https://fidoalliance.org/fido2/)
- [WebAuthn Standard](https://www.w3.org/TR/webauthn-2/)
- [Android Biometric API](https://developer.android.com/training/sign-in/biometric-auth)
