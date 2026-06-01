import mongoose, { Schema, type Document } from 'mongoose';
import type { AuthenticatorTransportFuture, Base64URLString } from '@simplewebauthn/server';

export interface ICredential extends Document {
  userId:      string;
  credentialId: Base64URLString;
  publicKey:   Buffer;
  signCount:   number;
  deviceType:  'singleDevice' | 'multiDevice';
  backedUp:    boolean;
  transports?: AuthenticatorTransportFuture[];
  createdAt:   Date;
}

const CredentialSchema = new Schema<ICredential>({
  userId:       { type: String,  required: true, index: true },
  credentialId: { type: String,  required: true, unique: true },
  publicKey:    { type: Buffer,  required: true },
  signCount:    { type: Number,  required: true, default: 0 },
  deviceType:   { type: String,  required: true, enum: ['singleDevice', 'multiDevice'] },
  backedUp:     { type: Boolean, required: true },
  transports:   [{ type: String }],
  createdAt:    { type: Date,    default: () => new Date() },
});

export const Credential = mongoose.model<ICredential>('Credential', CredentialSchema);
