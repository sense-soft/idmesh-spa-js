import Lock from 'browser-tabs-lock';

import {
  createQueryParams,
  runPopup,
  parseAuthenticationResult,
  encode,
  createRandomString,
  runIframe,
  sha256,
  bufferToBase64UrlEncoded,
  validateCrypto,
  openPopup,
  getDomain,
  getTokenIssuer,
  parseNumber
} from './utils';

import { oauthToken } from './api';

import { getUniqueScopes } from './scope';

import {
  InMemoryCache,
  ICache,
  CacheKey,
  CacheManager,
  CacheEntry,
  IdTokenEntry,
  CACHE_KEY_ID_TOKEN_SUFFIX,
  DecodedToken
} from './cache';

import { TransactionManager } from './transaction-manager';
import { verify as verifyIdToken } from './jwt';
import {
  AuthenticationError,
  GenericError,
  MissingRefreshTokenError,
  TimeoutError
} from './errors';

import {
  ClientStorage,
  CookieStorage,
  CookieStorageWithLegacySameSite,
  SessionStorage
} from './storage';

import {
  CACHE_LOCATION_MEMORY,
  DEFAULT_POPUP_CONFIG_OPTIONS,
  DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS,
  MISSING_REFRESH_TOKEN_ERROR_MESSAGE,
  DEFAULT_SCOPE,
  DEFAULT_SESSION_CHECK_EXPIRY_DAYS,
  DEFAULT_IDMESH_CLIENT,
  INVALID_REFRESH_TOKEN_ERROR_MESSAGE,
  DEFAULT_NOW_PROVIDER,
  DEFAULT_FETCH_TIMEOUT_MS
} from './constants';

import {
  IdmeshClientOptions,
  AuthorizationParams,
  AuthorizeOptions,
  RedirectLoginOptions,
  PopupLoginOptions,
  PopupConfigOptions,
  RedirectLoginResult,
  GetTokenSilentlyOptions,
  GetTokenWithPopupOptions,
  LogoutOptions,
  CacheLocation,
  LogoutUrlOptions,
  User,
  IdToken,
  GetTokenSilentlyVerboseResponse,
  TokenEndpointResponse
} from './global';


// @ts-ignore
import { singlePromise, retryPromise } from './promise-utils';
import { CacheKeyManifest } from './cache/key-manifest';
import {
  buildIsAuthenticatedCookieName,
  buildOrganizationHintCookieName,
  cacheFactory,
  getAuthorizeParams,
  GET_TOKEN_SILENTLY_LOCK_KEY,
  OLD_IS_AUTHENTICATED_COOKIE_NAME,
  patchOpenUrlWithOnRedirect
} from './IdmeshClient.utils';

type GetTokenSilentlyResult = TokenEndpointResponse & {
  decodedToken: ReturnType<typeof verifyIdToken>;
  scope: string;
  oauthTokenScope?: string;
  audience: string;
};

const lock = new Lock();

export class IdmeshClient {
  private readonly transactionManager: TransactionManager;
  private readonly cacheManager: CacheManager;
  private readonly domainUrl: string;
  private readonly tokenIssuer: string;
  private readonly scope: string;
  private readonly cookieStorage: ClientStorage;
  private readonly sessionCheckExpiryDays: number;
  private readonly orgHintCookieName: string;
  private readonly isAuthenticatedCookieName: string;
  private readonly nowProvider: () => number | Promise<number>;
  private readonly httpTimeoutMs: number;
  private readonly options: IdmeshClientOptions & {
    authorizationParams: AuthorizationParams;
  };
  private readonly userCache: ICache = new InMemoryCache().enclosedCache;

  private worker?: Worker;

  private readonly defaultOptions: Partial<IdmeshClientOptions> = {
    authorizationParams: {
      scope: DEFAULT_SCOPE
    },
    useRefreshTokensFallback: false,
    useFormData: true
  };

  constructor(options: IdmeshClientOptions) {
    this.options = {
      ...this.defaultOptions,
      ...options,
      authorizationParams: {
        ...this.defaultOptions.authorizationParams,
        ...options.authorizationParams
      }
    };

    typeof window !== 'undefined' && validateCrypto();

    if (options.cache && options.cacheLocation) {
      console.warn(
        'Both `cache` and `cacheLocation` options have been specified in the IdmeshClient configuration; ignoring `cacheLocation` and using `cache`.'
      );
    }

    let cacheLocation: CacheLocation | undefined;
    let cache: ICache;

    if (options.cache) {
      cache = options.cache;
    } else {
      cacheLocation = options.cacheLocation || CACHE_LOCATION_MEMORY;

      if (!cacheFactory(cacheLocation)) {
        throw new Error(`Invalid cache location "${cacheLocation}"`);
      }

      cache = cacheFactory(cacheLocation)();
    }

    this.httpTimeoutMs = options.httpTimeoutInSeconds
      ? options.httpTimeoutInSeconds * 1000
      : DEFAULT_FETCH_TIMEOUT_MS;

    this.cookieStorage =
      options.legacySameSiteCookie === false
        ? CookieStorage
        : CookieStorageWithLegacySameSite;

    this.orgHintCookieName = buildOrganizationHintCookieName(
      this.options.clientId
    );

    this.isAuthenticatedCookieName = buildIsAuthenticatedCookieName(
      this.options.clientId
    );

    this.sessionCheckExpiryDays =
      options.sessionCheckExpiryDays || DEFAULT_SESSION_CHECK_EXPIRY_DAYS;

    const transactionStorage = options.useCookiesForTransactions
      ? this.cookieStorage
      : SessionStorage;

    this.scope = getUniqueScopes(
      'openid',
      this.options.authorizationParams.scope,
      this.options.useRefreshTokens ? 'offline_access' : ''
    );

    this.transactionManager = new TransactionManager(
      transactionStorage,
      this.options.clientId
    );

    this.nowProvider = this.options.nowProvider || DEFAULT_NOW_PROVIDER;

    this.cacheManager = new CacheManager(
      cache,
      !cache.allKeys
        ? new CacheKeyManifest(cache, this.options.clientId)
        : undefined,
      this.nowProvider
    );

    this.domainUrl = getDomain(this.options.domain);
    this.tokenIssuer = getTokenIssuer(this.options.issuer, this.domainUrl);

  }

  private _url(path: string) {
    const idmeshClient = encodeURIComponent(
      btoa(JSON.stringify(this.options.idmeshClient || DEFAULT_IDMESH_CLIENT))
    );
    return `${this.domainUrl}${path}&idmeshClient=${idmeshClient}`;
  }

  private _authorizeUrl(authorizeOptions: AuthorizeOptions) {
    let queryParams = createQueryParams(authorizeOptions);
    console.log('queryParams', queryParams);
    return this._url(`/protocol/oidc/authorize?${queryParams}`);
  }

  private async _verifyIdToken(
    id_token: string,
    nonce?: string,
    organizationId?: string
  ) {
    const now = await this.nowProvider();

    return verifyIdToken({
      iss: this.tokenIssuer,
      aud: this.options.clientId,
      id_token,
      nonce,
      organizationId,
      leeway: this.options.leeway,
      max_age: parseNumber(this.options.authorizationParams.max_age),
      now
    });
  }

  private _processOrgIdHint(organizationId?: string) {
    if (organizationId) {
      this.cookieStorage.save(this.orgHintCookieName, organizationId, {
        daysUntilExpire: this.sessionCheckExpiryDays,
        cookieDomain: this.options.cookieDomain
      });
    } else {
      this.cookieStorage.remove(this.orgHintCookieName, {
        cookieDomain: this.options.cookieDomain
      });
    }
  }

  private async _prepareAuthorizeUrl(
    authorizationParams: AuthorizationParams,
    authorizeOptions?: Partial<AuthorizeOptions>,
    fallbackRedirectUri?: string
  ): Promise<{
    scope: string;
    audience: string;
    redirect_uri?: string;
    nonce: string;
    code_verifier: string;
    state: string;
    url: string;
  }> {
    const state = encode(createRandomString());
    const nonce = encode(createRandomString());
    const code_verifier = createRandomString();
    const code_challengeBuffer = await sha256(code_verifier);
    const code_challenge = bufferToBase64UrlEncoded(code_challengeBuffer);

    const params = getAuthorizeParams(
      this.options,
      this.scope,
      authorizationParams,
      state,
      nonce,
      code_challenge,
      authorizationParams.redirect_uri ||
        this.options.authorizationParams.redirect_uri ||
        fallbackRedirectUri,
      authorizeOptions?.response_mode
    );

    const url = this._authorizeUrl(params);

    return {
      nonce,
      code_verifier,
      scope: params.scope,
      audience: params.audience || 'default',
      redirect_uri: params.redirect_uri,
      state,
      url
    };
  }

  public async loginWithPopup(
    options?: PopupLoginOptions,
    config?: PopupConfigOptions
  ) {
    options = options || {};
    config = config || {};

    if (!config.popup) {
      config.popup = openPopup('');

      if (!config.popup) {
        throw new Error(
          'Unable to open a popup for loginWithPopup - window.open returned `null`'
        );
      }
    }

    const params = await this._prepareAuthorizeUrl(
      options.authorizationParams || {},
      { response_mode: 'web_message' },
      window.location.origin
    );

    config.popup.location.href = params.url;

    const codeResult = await runPopup({
      ...config,
      timeoutInSeconds:
        config.timeoutInSeconds ||
        this.options.authorizeTimeoutInSeconds ||
        DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS
    });

    if (params.state !== codeResult.state) {
      throw new Error('Invalid state');
    }

    const organizationId =
      options.authorizationParams?.organization ||
      this.options.authorizationParams.organization;

    await this._requestToken(
      {
        audience: params.audience,
        scope: params.scope,
        code_verifier: params.code_verifier,
        grant_type: 'authorization_code',
        code: codeResult.code as string,
        redirect_uri: params.redirect_uri
      },
      {
        nonceIn: params.nonce,
        organizationId
      }
    );
  }

  public async getUser<TUser extends User>(): Promise<TUser | undefined> {
    const cache = await this._getIdTokenFromCache();

    return cache?.decodedToken?.user as TUser;
  }

  public async getIdTokenClaims(): Promise<IdToken | undefined> {
    const cache = await this._getIdTokenFromCache();

    return cache?.decodedToken?.claims;
  }

  public async loginWithRedirect<TAppState = any>(
    options: RedirectLoginOptions<TAppState> = {}
  ) {
    const { openUrl, fragment, appState, ...urlOptions } =
      patchOpenUrlWithOnRedirect(options);

    const organizationId =
      urlOptions.authorizationParams?.organization ||
      this.options.authorizationParams.organization;

    const { url, ...transaction } = await this._prepareAuthorizeUrl(
      urlOptions.authorizationParams || {}
    );

    this.transactionManager.create({
      ...transaction,
      appState,
      ...(organizationId && { organizationId })
    });

    const urlWithFragment = fragment ? `${url}#${fragment}` : url;

    if (openUrl) {
      await openUrl(urlWithFragment);
    } else {
      window.location.assign(urlWithFragment);
    }
  }

  public async handleRedirectCallback<TAppState = any>(
    url: string = window.location.href
  ): Promise<RedirectLoginResult<TAppState>> {
    const queryStringFragments = url.split('?').slice(1);

    if (queryStringFragments.length === 0) {
      throw new Error('There are no query params available for parsing.');
    }

    const { state, code, error, error_description } = parseAuthenticationResult(
      queryStringFragments.join('')
    );

    const transaction = this.transactionManager.get();

    if (!transaction) {
      throw new Error('Invalid state');
    }

    this.transactionManager.remove();

    if (error) {
      throw new AuthenticationError(
        error,
        error_description || error,
        state,
        transaction.appState
      );
    }


    if (
      !transaction.code_verifier ||
      (transaction.state && transaction.state !== state)
    ) {
      throw new Error('Invalid state');
    }

    const organizationId = transaction.organizationId;
    const nonceIn = transaction.nonce;
    const redirect_uri = transaction.redirect_uri;

    await this._requestToken(
      {
        audience: transaction.audience,
        scope: transaction.scope,
        code_verifier: transaction.code_verifier,
        grant_type: 'authorization_code',
        code: code as string,
        ...(redirect_uri ? { redirect_uri } : {})
      },
      { nonceIn, organizationId }
    );

    return {
      appState: transaction.appState
    };
  }

  public async checkSession(options?: GetTokenSilentlyOptions) {
    if (!this.cookieStorage.get(this.isAuthenticatedCookieName)) {
      if (!this.cookieStorage.get(OLD_IS_AUTHENTICATED_COOKIE_NAME)) {
        return;
      } else {
        this.cookieStorage.save(this.isAuthenticatedCookieName, true, {
          daysUntilExpire: this.sessionCheckExpiryDays,
          cookieDomain: this.options.cookieDomain
        });

        this.cookieStorage.remove(OLD_IS_AUTHENTICATED_COOKIE_NAME);
      }
    }

    try {
      await this.getTokenSilently(options);
    } catch (_) {}
  }

  public async getTokenSilently(
    options: GetTokenSilentlyOptions & { detailedResponse: true }
  ): Promise<GetTokenSilentlyVerboseResponse>;

  public async getTokenSilently(
    options?: GetTokenSilentlyOptions
  ): Promise<string>;

  public async getTokenSilently(
    options: GetTokenSilentlyOptions = {}
  ): Promise<undefined | string | GetTokenSilentlyVerboseResponse> {
    const localOptions: GetTokenSilentlyOptions & {
      authorizationParams: AuthorizationParams & { scope: string };
    } = {
      cacheMode: 'on',
      ...options,
      authorizationParams: {
        ...this.options.authorizationParams,
        ...options.authorizationParams,
        scope: getUniqueScopes(this.scope, options.authorizationParams?.scope)
      }
    };

    const result = await singlePromise(
      () => this._getTokenSilently(localOptions),
      `${this.options.clientId}::${localOptions.authorizationParams.audience}::${localOptions.authorizationParams.scope}`
    );

    return options.detailedResponse ? result : result?.access_token;
  }

  private async _getTokenSilently(
    options: GetTokenSilentlyOptions & {
      authorizationParams: AuthorizationParams & { scope: string };
    }
  ): Promise<undefined | GetTokenSilentlyVerboseResponse> {
    const { cacheMode, ...getTokenOptions } = options;

    if (cacheMode !== 'off') {
      const entry = await this._getEntryFromCache({
        scope: getTokenOptions.authorizationParams.scope,
        audience: getTokenOptions.authorizationParams.audience || 'default',
        clientId: this.options.clientId
      });

      if (entry) {
        return entry;
      }
    }

    if (cacheMode === 'cache-only') {
      return;
    }

    if (
      await retryPromise(
        () => lock.acquireLock(GET_TOKEN_SILENTLY_LOCK_KEY, 5000),
        10
      )
    ) {
      try {
        window.addEventListener('pagehide', this._releaseLockOnPageHide);

        if (cacheMode !== 'off') {
          const entry = await this._getEntryFromCache({
            scope: getTokenOptions.authorizationParams.scope,
            audience: getTokenOptions.authorizationParams.audience || 'default',
            clientId: this.options.clientId
          });

          if (entry) {
            return entry;
          }
        }

        const authResult = this.options.useRefreshTokens
          ? await this._getTokenUsingRefreshToken(getTokenOptions)
          : await this._getTokenFromIFrame(getTokenOptions);

        const { id_token, access_token, oauthTokenScope, expires_in } =
          authResult;

        return {
          id_token,
          access_token,
          ...(oauthTokenScope ? { scope: oauthTokenScope } : null),
          expires_in
        };
      } finally {
        await lock.releaseLock(GET_TOKEN_SILENTLY_LOCK_KEY);
        window.removeEventListener('pagehide', this._releaseLockOnPageHide);
      }
    } else {
      throw new TimeoutError();
    }
  }

  public async getTokenWithPopup(
    options: GetTokenWithPopupOptions = {},
    config: PopupConfigOptions = {}
  ) {
    const localOptions = {
      ...options,
      authorizationParams: {
        ...this.options.authorizationParams,
        ...options.authorizationParams,
        scope: getUniqueScopes(this.scope, options.authorizationParams?.scope)
      }
    };

    config = {
      ...DEFAULT_POPUP_CONFIG_OPTIONS,
      ...config
    };

    await this.loginWithPopup(localOptions, config);

    const cache = await this.cacheManager.get(
      new CacheKey({
        scope: localOptions.authorizationParams.scope,
        audience: localOptions.authorizationParams.audience || 'default',
        clientId: this.options.clientId
      })
    );

    return cache!.access_token;
  }

  public async isAuthenticated() {
    const user = await this.getUser();
    return !!user;
  }

  private _buildLogoutUrl(options: LogoutUrlOptions): string {
    if (options.clientId !== null) {
      options.clientId = options.clientId || this.options.clientId;
    } else {
      delete options.clientId;
    }

    const { federated, ...logoutOptions } = options.logoutParams || {};
    const federatedQuery = federated ? `&federated` : '';
    const url = this._url(
      `/v2/logout?${createQueryParams({
        clientId: options.clientId,
        ...logoutOptions
      })}`
    );

    return url + federatedQuery;
  }

  public async logout(options: LogoutOptions = {}): Promise<void> {
    const { openUrl, ...logoutOptions } = patchOpenUrlWithOnRedirect(options);

    if (options.clientId === null) {
      await this.cacheManager.clear();
    } else {
      await this.cacheManager.clear(options.clientId || this.options.clientId);
    }

    this.cookieStorage.remove(this.orgHintCookieName, {
      cookieDomain: this.options.cookieDomain
    });
    this.cookieStorage.remove(this.isAuthenticatedCookieName, {
      cookieDomain: this.options.cookieDomain
    });
    this.userCache.remove(CACHE_KEY_ID_TOKEN_SUFFIX);

    const url = this._buildLogoutUrl(logoutOptions);

    if (openUrl) {
      await openUrl(url);
    } else if (openUrl !== false) {
      window.location.assign(url);
    }
  }

  private async _getTokenFromIFrame(
    options: GetTokenSilentlyOptions & {
      authorizationParams: AuthorizationParams & { scope: string };
    }
  ): Promise<GetTokenSilentlyResult> {
    const params: AuthorizationParams & { scope: string } = {
      ...options.authorizationParams,
      prompt: 'none'
    };

    const orgIdHint = this.cookieStorage.get<string>(this.orgHintCookieName);

    if (orgIdHint && !params.organization) {
      params.organization = orgIdHint;
    }

    const {
      url,
      state: stateIn,
      nonce: nonceIn,
      code_verifier,
      redirect_uri,
      scope,
      audience
    } = await this._prepareAuthorizeUrl(
      params,
      { response_mode: 'web_message' },
      window.location.origin
    );

    try {
      if ((window as any).crossOriginIsolated) {
        throw new GenericError(
          'login_required',
          'The application is running in a Cross-Origin Isolated context, silently retrieving a token without refresh token is not possible.'
        );
      }

      const authorizeTimeout =
        options.timeoutInSeconds || this.options.authorizeTimeoutInSeconds;

      const codeResult = await runIframe(url, this.domainUrl, authorizeTimeout);

      if (stateIn !== codeResult.state) {
        throw new Error('Invalid state');
      }

      const tokenResult = await this._requestToken(
        {
          ...options.authorizationParams,
          code_verifier,
          code: codeResult.code as string,
          grant_type: 'authorization_code',
          redirect_uri,
          timeout: options.authorizationParams.timeout || this.httpTimeoutMs
        },
        {
          nonceIn
        }
      );

      return {
        ...tokenResult,
        scope: scope,
        oauthTokenScope: tokenResult.scope,
        audience: audience
      };
    } catch (e) {
      if (e.error === 'login_required') {
        this.logout({
          openUrl: false
        });
      }
      throw e;
    }
  }

  private async _getTokenUsingRefreshToken(
    options: GetTokenSilentlyOptions & {
      authorizationParams: AuthorizationParams & { scope: string };
    }
  ): Promise<GetTokenSilentlyResult> {
    const cache = await this.cacheManager.get(
      new CacheKey({
        scope: options.authorizationParams.scope,
        audience: options.authorizationParams.audience || 'default',
        clientId: this.options.clientId
      })
    );

    if ((!cache || !cache.refresh_token) && !this.worker) {
      if (this.options.useRefreshTokensFallback) {
        return await this._getTokenFromIFrame(options);
      }

      throw new MissingRefreshTokenError(
        options.authorizationParams.audience || 'default',
        options.authorizationParams.scope
      );
    }

    const redirect_uri =
      options.authorizationParams.redirect_uri ||
      this.options.authorizationParams.redirect_uri ||
      window.location.origin;

    const timeout =
      typeof options.timeoutInSeconds === 'number'
        ? options.timeoutInSeconds * 1000
        : null;

    try {
      const tokenResult = await this._requestToken({
        ...options.authorizationParams,
        grant_type: 'refresh_token',
        refresh_token: cache && cache.refresh_token,
        redirect_uri,
        ...(timeout && { timeout })
      });

      return {
        ...tokenResult,
        scope: options.authorizationParams.scope,
        oauthTokenScope: tokenResult.scope,
        audience: options.authorizationParams.audience || 'default'
      };
    } catch (e) {
      if (
        (e.message.indexOf(MISSING_REFRESH_TOKEN_ERROR_MESSAGE) > -1 ||
          (e.message &&
            e.message.indexOf(INVALID_REFRESH_TOKEN_ERROR_MESSAGE) > -1)) &&
        this.options.useRefreshTokensFallback
      ) {
        return await this._getTokenFromIFrame(options);
      }

      throw e;
    }
  }

  private async _saveEntryInCache(
    entry: CacheEntry & { id_token: string; decodedToken: DecodedToken }
  ) {
    const { id_token, decodedToken, ...entryWithoutIdToken } = entry;

    this.userCache.set(CACHE_KEY_ID_TOKEN_SUFFIX, {
      id_token,
      decodedToken
    });

    await this.cacheManager.setIdToken(
      this.options.clientId,
      entry.id_token,
      entry.decodedToken
    );

    await this.cacheManager.set(entryWithoutIdToken);
  }

  private async _getIdTokenFromCache() {
    const audience = this.options.authorizationParams.audience || 'default';

    const cache = await this.cacheManager.getIdToken(
      new CacheKey({
        clientId: this.options.clientId,
        audience,
        scope: this.scope
      })
    );

    const currentCache = this.userCache.get<IdTokenEntry>(
      CACHE_KEY_ID_TOKEN_SUFFIX
    ) as IdTokenEntry;

    if (cache && cache.id_token === currentCache?.id_token) {
      return currentCache;
    }

    this.userCache.set(CACHE_KEY_ID_TOKEN_SUFFIX, cache);
    return cache;
  }

  private async _getEntryFromCache({
    scope,
    audience,
    clientId
  }: {
    scope: string;
    audience: string;
    clientId: string;
  }): Promise<undefined | GetTokenSilentlyVerboseResponse> {
    const entry = await this.cacheManager.get(
      new CacheKey({
        scope,
        audience,
        clientId
      }),
      60
    );

    if (entry && entry.access_token) {
      const { access_token, oauthTokenScope, expires_in } = entry as CacheEntry;
      const cache = await this._getIdTokenFromCache();
      return (
        cache && {
          id_token: cache.id_token,
          access_token,
          ...(oauthTokenScope ? { scope: oauthTokenScope } : null),
          expires_in
        }
      );
    }
  }

  private _releaseLockOnPageHide = async () => {
    await lock.releaseLock(GET_TOKEN_SILENTLY_LOCK_KEY);

    window.removeEventListener('pagehide', this._releaseLockOnPageHide);
  };

  private async _requestToken(
    options: PKCERequestTokenOptions | RefreshTokenRequestTokenOptions,
    additionalParameters?: RequestTokenAdditionalParameters
  ) {
    const { nonceIn, organizationId } = additionalParameters || {};
    const authResult = await oauthToken(
      {
        baseUrl: this.domainUrl,
        client_id: this.options.clientId,
        idmeshClient: this.options.idmeshClient,
        useFormData: this.options.useFormData,
        timeout: this.httpTimeoutMs,
        ...options
      },
      this.worker
    );

    const decodedToken = await this._verifyIdToken(
      authResult.id_token,
      nonceIn,
      organizationId
    );

    await this._saveEntryInCache({
      ...authResult,
      decodedToken,
      scope: options.scope,
      audience: options.audience || 'default',
      ...(authResult.scope ? { oauthTokenScope: authResult.scope } : null),
      client_id: this.options.clientId
    });

    this.cookieStorage.save(this.isAuthenticatedCookieName, true, {
      daysUntilExpire: this.sessionCheckExpiryDays,
      cookieDomain: this.options.cookieDomain
    });

    this._processOrgIdHint(decodedToken.claims.org_id);

    return { ...authResult, decodedToken };
  }
}

interface BaseRequestTokenOptions {
  audience?: string;
  scope: string;
  timeout?: number;
  redirect_uri?: string;
}

interface PKCERequestTokenOptions extends BaseRequestTokenOptions {
  code: string;
  grant_type: 'authorization_code';
  code_verifier: string;
}

interface RefreshTokenRequestTokenOptions extends BaseRequestTokenOptions {
  grant_type: 'refresh_token';
  refresh_token?: string;
}

interface RequestTokenAdditionalParameters {
  nonceIn?: string;
  organizationId?: string;
}
