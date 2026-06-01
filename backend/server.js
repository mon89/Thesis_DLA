"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const server_1 = require("@simplewebauthn/server");
const mongodb_1 = require("mongodb");
const RP_ID = process.env.RP_ID;
const ORIGIN = process.env.ORIGIN;
const RP_NAME = process.env.RP_NAME || 'Passkey Demo';
const PORT = parseInt(process.env.PORT || '3000', 10);
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI)
    throw new Error('MONGO_URI missing');
const client = new mongodb_1.MongoClient(MONGO_URI);
const app = (0, express_1.default)();
app.use(express_1.default.json({ limit: '1mb' }));
app.use((0, cors_1.default)({ origin: ORIGIN, credentials: true }));
const toB64 = (buf) => Buffer.from(buf).toString('base64url');
const fromB64 = (str) => Buffer.from(str, 'base64url');
async function initDb() {
    await client.connect();
    const db = client.db(); // uses DB from URI (e.g., /dla)
    const challenges = db.collection('challenges');
    const credentials = db.collection('credentials');
    await challenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await credentials.createIndex({ credentialId: 1 }, { unique: true });
    await credentials.createIndex({ userId: 1 });
    return { db, challenges, credentials };
}
async function main() {
    const { db, challenges, credentials } = await initDb();
    app.post('/webauthn/register/options', async (req, res) => {
        const { userId, email, displayName } = req.body;
        if (!email || !displayName)
            return res.status(400).json({ error: 'email and displayName required' });
        let uid = userId;
        if (!uid) {
            const r = await db.collection('users').insertOne({ email, displayName, createdAt: new Date() });
            uid = r.insertedId.toString();
        }
        const existing = await credentials.find({ userId: uid }).toArray();
        const options = await (0, server_1.generateRegistrationOptions)({
            rpName: RP_NAME,
            rpID: RP_ID,
            userID: uid,
            userName: email,
            userDisplayName: displayName,
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
            excludeCredentials: existing.map(c => ({ id: fromB64(c.credentialId), type: 'public-key' })),
        });
        await challenges.insertOne({
            userId: uid,
            type: 'registration',
            challenge: options.challenge,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
        });
        res.json({ userId: uid, options });
    });
    app.post('/webauthn/register/verify', async (req, res) => {
        const { userId, response } = req.body;
        if (!userId || !response)
            return res.status(400).json({ error: 'userId and response required' });
        const ch = await challenges.findOne({ userId, type: 'registration' });
        if (!ch)
            return res.status(400).json({ error: 'challenge expired' });
        const verification = await (0, server_1.verifyRegistrationResponse)({
            response,
            expectedChallenge: ch.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
        });
        if (!verification.verified)
            return res.status(400).json({ error: 'verification failed' });
        const { credentialPublicKey, credentialID, counter, credentialDeviceType, credentialBackedUp, transports } = verification.registrationInfo;
        await credentials.insertOne({
            userId,
            credentialId: toB64(credentialID),
            publicKey: credentialPublicKey,
            signCount: counter,
            deviceType: credentialDeviceType,
            backedUp: credentialBackedUp,
            transports,
            createdAt: new Date(),
        });
        await challenges.deleteMany({ userId, type: 'registration' });
        res.json({ ok: true });
    });
    app.post('/webauthn/authenticate/options', async (req, res) => {
        const { userId } = req.body;
        if (!userId)
            return res.status(400).json({ error: 'userId required' });
        const userCreds = await credentials.find({ userId }).toArray();
        if (!userCreds.length)
            return res.status(404).json({ error: 'no credentials for user' });
        const options = await (0, server_1.generateAuthenticationOptions)({
            rpID: RP_ID,
            allowCredentials: userCreds.map(c => ({
                id: fromB64(c.credentialId),
                type: 'public-key',
                transports: c.transports,
            })),
            userVerification: 'preferred',
        });
        await challenges.insertOne({
            userId,
            type: 'authentication',
            challenge: options.challenge,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
        });
        res.json({ options });
    });
    app.post('/webauthn/authenticate/verify', async (req, res) => {
        const { userId, response } = req.body;
        if (!userId || !response)
            return res.status(400).json({ error: 'userId and response required' });
        const ch = await challenges.findOne({ userId, type: 'authentication' });
        if (!ch)
            return res.status(400).json({ error: 'challenge expired' });
        const cred = await credentials.findOne({ credentialId: response.id, userId });
        if (!cred)
            return res.status(404).json({ error: 'credential not found' });
        const verification = await (0, server_1.verifyAuthenticationResponse)({
            response,
            expectedChallenge: ch.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            authenticator: {
                credentialID: fromB64(cred.credentialId),
                credentialPublicKey: cred.publicKey.buffer ? Buffer.from(cred.publicKey.buffer) : cred.publicKey,
                counter: cred.signCount,
                transports: cred.transports,
            },
        });
        if (!verification.verified)
            return res.status(400).json({ error: 'verification failed' });
        await credentials.updateOne({ _id: cred._id }, { $set: { signCount: verification.authenticationInfo.newCounter } });
        await challenges.deleteMany({ userId, type: 'authentication' });
        res.json({ ok: true, token: 'placeholder-jwt' }); // TODO issue real JWT/session
    });
    app.get('/health', (_req, res) => res.json({ ok: true, rpId: RP_ID }));
    app.listen(PORT, () => console.log(`WebAuthn server on ${PORT}`));
}
main().catch(err => {
    console.error(err);
    process.exit(1);
});
//# sourceMappingURL=server.js.map