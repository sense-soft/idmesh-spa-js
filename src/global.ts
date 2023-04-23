import {ICache} from './cache';

export interface AuthorizationParams {

    display?: 'page' | 'popup' | 'touch' | 'wap';

    prompt?: 'none' | 'login' | 'consent' | 'select_account';

    max_age?: string | number;

    ui_locales?: string;

    id_token_hint?: string;

    screen_hint?: 'signup' | 'login' | string;

    login_hint?: string;

    acr_values?: string;

    scope?: string;

    audience?: string;

    connection?: string;

    organization?: string;

    invitation?: string;

    redirect_uri?: string;

    [key: string]: any;
}

interface BaseLoginOptions {
    authorizationParams?: AuthorizationParams;
}

export interface IdmeshClientOptions extends BaseLoginOptions {
    domain: string;
    issuer?: string;
    clientId: string;
    leeway?: number;
    cacheLocation?: CacheLocation;
    cache?: ICache;
    useRefreshTokens?: boolean;
    useRefreshTokensFallback?: boolean;
    authorizeTimeoutInSeconds?: number;
    httpTimeoutInSeconds?: number;
    idmeshClient?: {
        name: string;
        version: string;
        env?: { [key: string]: string };
    };

    legacySameSiteCookie?: boolean;
    useCookiesForTransactions?: boolean;
    sessionCheckExpiryDays?: number;
    cookieDomain?: string;
    useFormData?: boolean;
    nowProvider?: () => Promise<number> | number;
}

export type CacheLocation = 'memory' | 'localstorage';

export interface AuthorizeOptions extends AuthorizationParams {
    response_type: string;
    response_mode: string;
    redirect_uri?: string;
    nonce: string;
    state: string;
    scope: string;
    code_challenge: string;
    code_challenge_method: string;
}

export interface RedirectLoginOptions<TAppState = any>
    extends BaseLoginOptions {

    appState?: TAppState;

    fragment?: string;

    onRedirect?: (url: string) => Promise<void>;

    openUrl?: (url: string) => Promise<void>;
}

export interface RedirectLoginResult<TAppState = any> {

    appState?: TAppState;
}

export interface PopupLoginOptions extends BaseLoginOptions {
}

export interface PopupConfigOptions {

    timeoutInSeconds?: number;

    popup?: any;
}

export interface GetTokenSilentlyOptions {
    cacheMode?: 'on' | 'off' | 'cache-only';

    authorizationParams?: {
        redirect_uri?: string;

        scope?: string;

        audience?: string;

        [key: string]: any;
    };

    timeoutInSeconds?: number;

    detailedResponse?: boolean;
}

export interface GetTokenWithPopupOptions extends PopupLoginOptions {

    cacheMode?: 'on' | 'off' | 'cache-only';
}

export interface LogoutUrlOptions {
    clientId?: string | null;
    logoutParams?: {
        federated?: boolean;
        returnTo?: string;

        [key: string]: any;
    };
}

export interface LogoutOptions extends LogoutUrlOptions {

    onRedirect?: (url: string) => Promise<void>;

    openUrl?: false | ((url: string) => Promise<void>);
}

export interface AuthenticationResult {
    state: string;
    code?: string;
    error?: string;
    error_description?: string;
}

export interface TokenEndpointOptions {
    baseUrl: string;
    client_id: string;
    grant_type: string;
    timeout?: number;
    idmeshClient: any;
    useFormData?: boolean;

    [key: string]: any;
}

export type TokenEndpointResponse = {
    id_token: string;
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    scope?: string;
};

export interface OAuthTokenOptions extends TokenEndpointOptions {
    code_verifier: string;
    code: string;
    redirect_uri: string;
    audience: string;
    scope: string;
}

export interface RefreshTokenOptions extends TokenEndpointOptions {
    refresh_token: string;
}

export interface JWTVerifyOptions {
    iss: string;
    aud: string;
    id_token: string;
    nonce?: string;
    leeway?: number;
    max_age?: number;
    organizationId?: string;
    now?: number;
}

export interface IdToken {
    issuer?: string;
    audience?: any;
    expiration?: string;
    not_before?: string;
    issued_at?: string;
    jwt_id?: string;
    authorized_party?: string;
    nonce?: string;
    auth_time?: string;
    access_token_hash?: string;
    code_hash?: string;
    authentication_context_class_reference?: string;
    authentication_methods_references?: string[];
    client_id?: string;
    user_info?: User;

    [key: string]: any;
}

export class User {
    name?: string;
    username?: string;
    nickname?: string;
    email?: string;
    phone?: string;
    profile?: string;
    gender?: string;
}

export type FetchOptions = {
    /** A BodyInit object or null to set request's body. */
    body?: BodyInit | null;
    /** A string indicating how the request will interact with the browser's cache to set request's cache. */
    cache?: RequestCache;
    /** A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL. Sets request's credentials. */
    credentials?: RequestCredentials;
    /** A Headers object, an object literal, or an array of two-item arrays to set request's headers. */
    headers?: HeadersInit;
    /** A cryptographic hash of the resource to be fetched by request. Sets request's integrity. */
    integrity?: string;
    /** A boolean to set request's keepalive. */
    keepalive?: boolean;
    /** A string to set request's method. */
    method?: string;
    /** A string to indicate whether the request will use CORS, or will be restricted to same-origin URLs. Sets request's mode. */
    mode?: RequestMode;
    /** A string indicating whether request follows redirects, results in an error upon encountering a redirect, or returns the redirect (in an opaque fashion). Sets request's redirect. */
    redirect?: RequestRedirect;
    /** A string whose value is a same-origin URL, "about:client", or the empty string, to set request's referrer. */
    referrer?: string;
    /** A referrer policy to set request's referrerPolicy. */
    referrerPolicy?: ReferrerPolicy;
    /** An AbortSignal to set request's signal. */
    signal?: AbortSignal | null;
    /** Can only be null. Used to disassociate request from any Window. */
    window?: null;
};

export type GetTokenSilentlyVerboseResponse = Omit<
    TokenEndpointResponse,
    'refresh_token'
>;
