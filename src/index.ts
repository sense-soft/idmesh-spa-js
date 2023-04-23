import { IdmeshClient } from './IdmeshClient';
import { IdmeshClientOptions } from './global';

import './global';

export * from './global';

export async function createIdmeshClient(options: IdmeshClientOptions) {
  const idmesh = new IdmeshClient(options);
  await idmesh.checkSession();
  return idmesh;
}

export { IdmeshClient };

export {
  GenericError,
  AuthenticationError,
  TimeoutError,
  PopupTimeoutError,
  PopupCancelledError,
  MfaRequiredError,
  MissingRefreshTokenError
} from './errors';

export {
  ICache,
  LocalStorageCache,
  InMemoryCache,
  Cacheable,
  DecodedToken,
  CacheEntry,
  WrappedCacheEntry,
  KeyManifestEntry,
  MaybePromise,
  CacheKey,
  CacheKeyData
} from './cache';
