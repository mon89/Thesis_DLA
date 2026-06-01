import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type AuthFlow =
  | 'BOOTSTRAP'
  | 'TRUSTED_DEVICE'
  | 'NEW_DEVICE'
  | 'NEWLY_APPROVED'
  | 'BLOCKED'
  | 'FAILED';

export type AuthOutcome =
  | 'SUCCESS'
  | 'FAILED_PASSKEY'
  | 'FAILED_DBK'
  | 'PENDING_APPROVAL'
  | 'BLOCKED'
  | 'ERROR';

export interface IAuthenticationLog extends Document {
  userId?:    Types.ObjectId;
  username?:  string;
  deviceId?:  string;
  ip?:        string;
  userAgent?: string;
  flow:       AuthFlow;
  outcome:    AuthOutcome;
  latency: {
    passkeyOptionsMs?:  number;
    passkeyVerifyMs?:   number;
    passkeyTotalMs?:    number;
    challengeMs?:       number;
    dbkVerifyMs?:       number;
    deviceLookupMs?:    number;
    deviceTotalMs?:     number;
    totalMs?:           number;
    clientDbkGenMs?:    number;
    clientDbkSignMs?:   number;
    clientTotalMs?:     number;
  };
  errorMessage?: string;
  errorStep?:    string;
  createdAt:     Date;
}

const latencySchema = new Schema(
  {
    passkeyOptionsMs: Number,
    passkeyVerifyMs:  Number,
    passkeyTotalMs:   Number,
    challengeMs:      Number,
    dbkVerifyMs:      Number,
    deviceLookupMs:   Number,
    deviceTotalMs:    Number,
    totalMs:          Number,
    clientDbkGenMs:   Number,
    clientDbkSignMs:  Number,
    clientTotalMs:    Number,
  },
  { _id: false },
);

const AuthenticationLogSchema = new Schema<IAuthenticationLog>(
  {
    userId:    { type: Schema.Types.ObjectId, ref: 'User' },
    username:  { type: String },
    deviceId:  { type: String },
    ip:        { type: String },
    userAgent: { type: String },
    flow:      { type: String, required: true, enum: ['BOOTSTRAP','TRUSTED_DEVICE','NEW_DEVICE','NEWLY_APPROVED','BLOCKED','FAILED'] },
    outcome:   { type: String, required: true, enum: ['SUCCESS','FAILED_PASSKEY','FAILED_DBK','PENDING_APPROVAL','BLOCKED','ERROR'] },
    latency:   { type: latencySchema, default: () => ({}) },
    errorMessage: { type: String },
    errorStep:    { type: String },
    createdAt:    { type: Date, default: () => new Date() },
  },
  { _id: true },
);

AuthenticationLogSchema.index({ createdAt: -1 });
AuthenticationLogSchema.index({ flow: 1, outcome: 1 });
AuthenticationLogSchema.index({ userId: 1, createdAt: -1 });

export const AuthenticationLog = mongoose.model<IAuthenticationLog>('AuthenticationLog', AuthenticationLogSchema);
