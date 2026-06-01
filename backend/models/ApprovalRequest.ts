import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'CONSUMED' | 'DENIED' | 'EXPIRED';

export interface IApprovalRequest extends Document {
  userId:              Types.ObjectId;
  requestingDeviceId:  string;
  approverDeviceId:    string;
  loginAttemptId:      string;
  status:              ApprovalStatus;
  requestContext: {
    userAgent:   string;
    platform:    string;
    timezone:    string;
    ip:          string;
    requestedAt: Date;
  };
  expiresAt:   Date;
  resolvedAt?: Date;
  createdAt:   Date;
}

const ApprovalRequestSchema = new Schema<IApprovalRequest>(
  {
    userId:             { type: Schema.Types.ObjectId, ref: 'User', required: true },
    requestingDeviceId: { type: String, required: true },
    approverDeviceId:   { type: String, required: true },
    loginAttemptId:     { type: String, required: true },
    status:             { type: String, required: true, enum: ['PENDING', 'APPROVED', 'CONSUMED', 'DENIED', 'EXPIRED'], default: 'PENDING' },

    requestContext: {
      userAgent:   { type: String, default: '' },
      platform:    { type: String, default: '' },
      timezone:    { type: String, default: '' },
      ip:          { type: String, default: '' },
      requestedAt: { type: Date,   default: () => new Date() },
    },

    expiresAt:  { type: Date, required: true, default: () => new Date(Date.now() + 5 * 60 * 1000) },
    resolvedAt: { type: Date },
    createdAt:  { type: Date, default: () => new Date() },
  },
  { _id: true },
);

ApprovalRequestSchema.index({ userId: 1, status: 1 });
ApprovalRequestSchema.index({ loginAttemptId: 1 });
ApprovalRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const ApprovalRequest = mongoose.model<IApprovalRequest>('ApprovalRequest', ApprovalRequestSchema);
