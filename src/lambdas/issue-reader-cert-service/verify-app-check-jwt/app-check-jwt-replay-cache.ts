import { emptyFailure, emptySuccess, Result } from '../../common/result/result';

export interface JwtReplayCache {
  consume(jti: string, expEpochSeconds: number): Result<void, void>;
}

export class InMemoryJwtReplayCache implements JwtReplayCache {
  private static INSTANCE: JwtReplayCache;
  private readonly expEpochMillisByJti = new Map<string, number>();

  static getSingletonInstance(
    nowInMillis: () => number = Date.now,
  ): JwtReplayCache {
    if (!this.INSTANCE) this.INSTANCE = new InMemoryJwtReplayCache(nowInMillis);
    return this.INSTANCE;
  }

  constructor(private readonly nowInMillis: () => number = Date.now) {}

  consume(jti: string, expEpochSeconds: number): Result<void, void> {
    this.deleteExpiredEntries();

    const now = this.nowInMillis();
    const existingExpEpochMillis = this.expEpochMillisByJti.get(jti);
    if (existingExpEpochMillis !== undefined && existingExpEpochMillis >= now) {
      return emptyFailure();
    }

    this.expEpochMillisByJti.set(jti, expEpochSeconds * 1000);
    return emptySuccess();
  }

  private deleteExpiredEntries() {
    const now = this.nowInMillis();
    for (const [jti, expEpochMillis] of this.expEpochMillisByJti.entries()) {
      if (expEpochMillis <= now) {
        this.expEpochMillisByJti.delete(jti);
      }
    }
  }
}
