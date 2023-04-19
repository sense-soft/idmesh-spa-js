import { ICache, InMemoryCache, LocalStorageCache } from './cache';
import {
  IdmeshClientOptions,
  AuthorizationParams,
  AuthorizeOptions,
  LogoutOptions
} from './global';
import { getUniqueScopes } from './scope';

export const GET_TOKEN_SILENTLY_LOCK_KEY = 'idmesh.lock.getTokenSilently';

export const buildOrganizationHintCookieName = (clientId: string) =>
  `idmesh.${clientId}.organization_hint`;

export const OLD_IS_AUTHENTICATED_COOKIE_NAME = 'idmesh.is.authenticated';

export const buildIsAuthenticatedCookieName = (clientId: string) =>
  `idmesh.${clientId}.is.authenticated`;

const cacheLocationBuilders: Record<string, () => ICache> = {
  memory: () => new InMemoryCache().enclosedCache,
  localstorage: () => new LocalStorageCache()
};

export const cacheFactory = (location: string) => {
  return cacheLocationBuilders[location];
};

export const getAuthorizeParams = (
  clientOptions: IdmeshClientOptions & {
    authorizationParams: AuthorizationParams;
  },
  scope: string,
  authorizationParams: AuthorizationParams,
  state: string,
  nonce: string,
  code_challenge: string,
  redirect_uri: string | undefined,
  response_mode: string | undefined
): AuthorizeOptions => {
  return {
    client_id: clientOptions.clientId,
    ...clientOptions.authorizationParams,
    ...authorizationParams,
    scope: getUniqueScopes(scope, authorizationParams.scope),
    response_type: 'code',
    response_mode: response_mode || 'query',
    state,
    nonce,
    redirect_uri:
      redirect_uri || clientOptions.authorizationParams.redirect_uri,
    code_challenge,
    code_challenge_method: 'S256'
  };
};

export const patchOpenUrlWithOnRedirect = <
  T extends Pick<LogoutOptions, 'openUrl' | 'onRedirect'>
>(
  options: T
) => {
  const { openUrl, onRedirect, ...originalOptions } = options;

  const result = {
    ...originalOptions,
    openUrl: openUrl === false || openUrl ? openUrl : onRedirect
  };

  return result as T;
};
