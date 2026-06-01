import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type AuditEvent =
  | 'DBK_SIGNATURE_INVALID'
  | 'DBK_CHALLENGE_EXPIRED'
  | 'PASSKEY_AUTH_SUCCESS'
  | 'PASSKEY_AUTH_FAILED'
  | 'DEVICE_BLOCKED'
  | 'DEVICE_ENROLLED_BOOTSTRAP'
  | 'DEVICE_ENROLLED_PENDING'
  | 'DEVICE_APPROVED'
  | 'DEVICE_DENIED'
  | 'APPROVAL_REQUESTED'
  | 'APPROVAL_EXPIRED'
  | 'SESSION_DEVICE_MISMATCH'
  | 'UNAUTHENTICATED_ACCESS'
  | 'BOOTSTRAP_RACE_DETECTED'
  | 'FINALIZE_INVALID_SIGNATURE'
  | 'APPROVAL_SIGNATURE_INVALID';

export type AuditSeverity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface IAuditLog extends Document {
  event:        AuditEvent;
  severity:     AuditSeverity;
  userId?:      Types.ObjectId;
  username?:    string;
  deviceId?:    string;
  message:      string;
  details?:     unknown;
  ip?:          string;
  userAgent?:   string;
  attackVector?: string;
  mitigated:    boolean;
  createdAt:    Date;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    event: {
      type:     String,
      required: true,
      enum:     ['DBK_SIGNATURE_INVALID','DBK_CHALLENGE_EXPIRED','PASSKEY_AUTH_SUCCESS',
                 'PASSKEY_AUTH_FAILED','DEVICE_BLOCKED','DEVICE_ENROLLED_BOOTSTRAP',
                 'DEVICE_ENROLLED_PENDING','DEVICE_APPROVED','DEVICE_DENIED',
                 'APPROVAL_REQUESTED','APPROVAL_EXPIRED','SESSION_DEVICE_MISMATCH',
                 'UNAUTHENTICATED_ACCESS','BOOTSTRAP_RACE_DETECTED',
                 'FINALIZE_INVALID_SIGNATURE','APPROVAL_SIGNATURE_INVALID'],
    },
    severity:     { type: String, required: true, enum: ['INFO','WARNING','CRITICAL'], default: 'INFO' },
    userId:       { type: Schema.Types.ObjectId, ref: 'User' },
    username:     { type: String },
    deviceId:     { type: String },
    message:      { type: String, required: true },
    details:      { type: Schema.Types.Mixed },
    ip:           { type: String },
    userAgent:    { type: String },
    attackVector: { type: String },
    mitigated:    { type: Boolean, default: true },
    createdAt:    { type: Date, default: () => new Date() },
  },
  { _id: true },
);

AuditLogSchema.index({ event: 1, createdAt: -1 });
AuditLogSchema.index({ severity: 1, createdAt: -1 });
AuditLogSchema.index({ attackVector: 1, mitigated: 1 });

export const AuditLog = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
