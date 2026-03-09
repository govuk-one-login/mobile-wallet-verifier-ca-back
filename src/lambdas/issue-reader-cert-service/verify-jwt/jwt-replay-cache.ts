export interface JwtReplayCache {
  consume(jti: string, expEpochSeconds: number): boolean;
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

  consume(jti: string, expEpochSeconds: number): boolean {
    this.deleteExpiredEntries();

    const now = this.nowInMillis();
    const existingExpEpochMillis = this.expEpochMillisByJti.get(jti);
    if (existingExpEpochMillis !== undefined && existingExpEpochMillis > now) {
      return false;
    }

    this.expEpochMillisByJti.set(jti, expEpochSeconds * 1000);
    return true;
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
