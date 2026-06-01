import 'express-session';

declare module 'express-session' {
  interface SessionData {
    passkeyVerified?: {
      userId:     string;
      username:   string;
      verifiedAt: number;
    };
    dbkChallenge?: {
      challenge:          string;
      userId:             string;
      expectedDeviceId:   string;
      expectedPubKey:     object;
      loginAttemptId:     string;
      createdAt:          number;
      expiresAt:          number;
      trustedDeviceCount: number;
    };
    authenticated?: {
      userId:          string;
      username:        string;
      deviceId:        string;
      deviceStatus:    string;
      authenticatedAt: number;
    };
    registering?: {
      userId:   string;
      username: string;
    };
    authenticating?: {
      userId:   string;
      username: string;
    };
  }
}
