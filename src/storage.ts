import * as Cookies from 'es-cookie';

interface ClientStorageOptions {
  daysUntilExpire?: number;
  cookieDomain?: string;
}

export type ClientStorage = {
  get<T extends Object>(key: string): T | undefined;
  save(key: string, value: any, options?: ClientStorageOptions): void;
  remove(key: string, options?: ClientStorageOptions): void;
};

export const CookieStorage = {
  get<T extends Object>(key: string) {
    const value = Cookies.get(key);

    if (typeof value === 'undefined') {
      return;
    }

    return <T>JSON.parse(value);
  },

  save(key: string, value: any, options?: ClientStorageOptions): void {
    let cookieAttributes: Cookies.CookieAttributes = {};

    if ('https:' === window.location.protocol) {
      cookieAttributes = {
        secure: true,
        sameSite: 'none'
      };
    }

    if (options?.daysUntilExpire) {
      cookieAttributes.expires = options.daysUntilExpire;
    }

    if (options?.cookieDomain) {
      cookieAttributes.domain = options.cookieDomain;
    }

    Cookies.set(key, JSON.stringify(value), cookieAttributes);
  },

  remove(key: string, options?: ClientStorageOptions) {
    let cookieAttributes: Cookies.CookieAttributes = {};

    if (options?.cookieDomain) {
      cookieAttributes.domain = options.cookieDomain;
    }

    Cookies.remove(key, cookieAttributes);
  }
} as ClientStorage;

const LEGACY_PREFIX = '_idmesh_legacy_';


export const CookieStorageWithLegacySameSite = {
  get<T extends Object>(key: string) {
    const value = CookieStorage.get<T>(key);

    if (value) {
      return value;
    }

    return CookieStorage.get<T>(`${LEGACY_PREFIX}${key}`);
  },

  save(key: string, value: any, options?: ClientStorageOptions): void {
    let cookieAttributes: Cookies.CookieAttributes = {};

    if ('https:' === window.location.protocol) {
      cookieAttributes = { secure: true };
    }

    if (options?.daysUntilExpire) {
      cookieAttributes.expires = options.daysUntilExpire;
    }

    if (options?.cookieDomain) {
      cookieAttributes.domain = options.cookieDomain;
    }

    Cookies.set(
      `${LEGACY_PREFIX}${key}`,
      JSON.stringify(value),
      cookieAttributes
    );
    CookieStorage.save(key, value, options);
  },

  remove(key: string, options?: ClientStorageOptions) {
    let cookieAttributes: Cookies.CookieAttributes = {};

    if (options?.cookieDomain) {
      cookieAttributes.domain = options.cookieDomain;
    }

    Cookies.remove(key, cookieAttributes);
    CookieStorage.remove(key, options);
    CookieStorage.remove(`${LEGACY_PREFIX}${key}`, options);
  }
} as ClientStorage;

export const SessionStorage = {
  get<T extends Object>(key: string) {
    if (typeof sessionStorage === 'undefined') {
      return;
    }

    const value = sessionStorage.getItem(key);

    if (value == null) {
      return;
    }

    return <T>JSON.parse(value);
  },

  save(key: string, value: any): void {
    sessionStorage.setItem(key, JSON.stringify(value));
  },

  remove(key: string) {
    sessionStorage.removeItem(key);
  }
} as ClientStorage;
