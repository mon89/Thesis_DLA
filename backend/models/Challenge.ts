import mongoose, { Schema, type Document } from 'mongoose';

export type ChallengeType = 'registration' | 'authentication';

export interface IChallenge extends Document {
  userId:    string;
  type:      ChallengeType;
  challenge: string;
  expiresAt: Date;
}

const ChallengeSchema = new Schema<IChallenge>({
  userId:    { type: String, required: true },
  type:      { type: String, required: true, enum: ['registration', 'authentication'] },
  challenge: { type: String, required: true },
  expiresAt: { type: Date,   required: true },
});

// TTL index: MongoDB auto-removes documents when expiresAt is reached
ChallengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const Challenge = mongoose.model<IChallenge>('Challenge', ChallengeSchema);
