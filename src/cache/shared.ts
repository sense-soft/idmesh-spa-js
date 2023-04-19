import { IdToken, User } from '../global';

export const CACHE_KEY_PREFIX = '@@idmeshspajs@@';
export const CACHE_KEY_ID_TOKEN_SUFFIX = '@@user@@';

export type CacheKeyData = {
  audience?: string;
  scope?: string;
  clientId: string;
};

export class CacheKey {
  public clientId: string;
  public scope?: string;
  public audience?: string;

  constructor(
    data: CacheKeyData,
    public prefix: string = CACHE_KEY_PREFIX,
    public suffix?: string
  ) {
    this.clientId = data.clientId;
    this.scope = data.scope;
    this.audience = data.audience;
  }

  toKey(): string {
    return [this.prefix, this.clientId, this.audience, this.scope, this.suffix]
      .filter(Boolean)
      .join('::');
  }

  static fromKey(key: string): CacheKey {
    const [prefix, clientId, audience, scope] = key.split('::');

    return new CacheKey({ clientId, scope, audience }, prefix);
  }

  static fromCacheEntry(entry: CacheEntry): CacheKey {
    const { scope, audience, client_id: clientId } = entry;

    return new CacheKey({
      scope,
      audience,
      clientId
    });
  }
}

export interface DecodedToken {
  claims: IdToken;
  user: User;
}

export interface IdTokenEntry {
  id_token: string;
  decodedToken: DecodedToken;
}

export type CacheEntry = {
  id_token?: string;
  access_token: string;
  expires_in: number;
  decodedToken?: DecodedToken;
  audience: string;
  scope: string;
  client_id: string;
  refresh_token?: string;
  oauthTokenScope?: string;
};

export type WrappedCacheEntry = {
  body: Partial<CacheEntry>;
  expiresAt: number;
};

export type KeyManifestEntry = {
  keys: string[];
};

export type Cacheable = WrappedCacheEntry | KeyManifestEntry;

export type MaybePromise<T> = Promise<T> | T;

export interface ICache {
  set<T = Cacheable>(key: string, entry: T): MaybePromise<void>;
  get<T = Cacheable>(key: string): MaybePromise<T | undefined>;
  remove(key: string): MaybePromise<void>;
  allKeys?(): MaybePromise<string[]>;
}
