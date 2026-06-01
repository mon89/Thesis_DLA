import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type DeviceStatus = 'TRUSTED' | 'PENDING' | 'REJECTED' | 'REVOKED';

export interface IDeviceProfile extends Document {
  deviceId:   string;
  userId:     Types.ObjectId;
  dbkPublicKey: string;
  status:     DeviceStatus;
  approvedBy?: {
    deviceId:   string;
    approvedAt: Date;
  };
  enrollmentSignals: {
    userAgent:  string;
    platform:   string;
    timezone:   string;
    ip:         string;
    enrolledAt: Date;
  };
  lastAuthSignals?: {
    ip:        string;
    timezone:  string;
    userAgent: string;
    loginAt:   Date;
  };
  createdAt:  Date;
  updatedAt:  Date;
}

const DeviceProfileSchema = new Schema<IDeviceProfile>(
  {
    deviceId:     { type: String, required: true },
    userId:       { type: Schema.Types.ObjectId, ref: 'User', required: true },
    dbkPublicKey: { type: String, required: true },
    status:       { type: String, required: true, enum: ['TRUSTED', 'PENDING', 'REJECTED', 'REVOKED'], default: 'PENDING' },

    approvedBy: {
      deviceId:   { type: String },
      approvedAt: { type: Date },
    },

    enrollmentSignals: {
      userAgent:  { type: String, default: '' },
      platform:   { type: String, default: '' },
      timezone:   { type: String, default: '' },
      ip:         { type: String, default: '' },
      enrolledAt: { type: Date,   default: () => new Date() },
    },

    lastAuthSignals: {
      ip:        { type: String },
      timezone:  { type: String },
      userAgent: { type: String },
      loginAt:   { type: Date },
    },

    createdAt: { type: Date, default: () => new Date() },
    updatedAt: { type: Date, default: () => new Date() },
  },
  { _id: true },
);

// Compound unique: one deviceId per user
DeviceProfileSchema.index({ userId: 1, deviceId: 1 }, { unique: true });
DeviceProfileSchema.index({ userId: 1, status: 1 });

// Pre-save: always update updatedAt
DeviceProfileSchema.pre('save', async function () {
  this.updatedAt = new Date();
});

export const DeviceProfile = mongoose.model<IDeviceProfile>('DeviceProfile', DeviceProfileSchema);
