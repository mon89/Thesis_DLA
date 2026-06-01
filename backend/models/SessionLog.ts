import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type SessionEvent =
  | 'SESSION_CREATED'
  | 'PASSKEY_VERIFIED'
  | 'DEVICE_VERIFIED'
  | 'SESSION_EXPIRED'
  | 'SESSION_DESTROYED'
  | 'DEVICE_MISMATCH'
  | 'SESSION_REFRESH';

export interface ISessionLog extends Document {
  sessionId:          string;
  userId?:            Types.ObjectId;
  username?:          string;
  deviceId?:          string;
  event:              SessionEvent;
  ip?:                string;
  userAgent?:         string;
  timezone?:          string;
  expectedDeviceId?:  string;
  actualDeviceId?:    string;
  createdAt:          Date;
}

const SessionLogSchema = new Schema<ISessionLog>(
  {
    sessionId:         { type: String, required: true },
    userId:            { type: Schema.Types.ObjectId, ref: 'User' },
    username:          { type: String },
    deviceId:          { type: String },
    event:             {
      type:     String,
      required: true,
      enum:     ['SESSION_CREATED','PASSKEY_VERIFIED','DEVICE_VERIFIED',
                 'SESSION_EXPIRED','SESSION_DESTROYED','DEVICE_MISMATCH','SESSION_REFRESH'],
    },
    ip:                { type: String },
    userAgent:         { type: String },
    timezone:          { type: String },
    expectedDeviceId:  { type: String },
    actualDeviceId:    { type: String },
    createdAt:         { type: Date, default: () => new Date() },
  },
  { _id: true },
);

SessionLogSchema.index({ sessionId: 1, createdAt: -1 });
SessionLogSchema.index({ event: 1, createdAt: -1 });

export const SessionLog = mongoose.model<ISessionLog>('SessionLog', SessionLogSchema);
