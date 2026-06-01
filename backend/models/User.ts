import mongoose, { Schema, type Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  displayName: string;
  createdAt: Date;
}

const UserSchema = new Schema<IUser>({
  email:       { type: String, required: true, unique: true, lowercase: true, trim: true },
  displayName: { type: String, required: true, trim: true },
  createdAt:   { type: Date,   default: () => new Date() },
});

export const User = mongoose.model<IUser>('User', UserSchema);
