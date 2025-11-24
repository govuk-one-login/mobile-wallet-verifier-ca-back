import { UUID } from 'node:crypto';

export interface NonceTableItem {
  nonceValue: UUID;
  timeToLive: number;
  expiresAt: string;
}
