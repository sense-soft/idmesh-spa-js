import { urlDecodeB64 } from './utils';
import { IdToken, JWTVerifyOptions } from './global';

export const decode = (token: string) => {
  const parts = token.split('.');
  const [header, payload, signature] = parts;

  if (parts.length !== 3 || !header || !payload || !signature) {
    throw new Error('ID token could not be decoded');
  }
  const claims:IdToken = JSON.parse(atob(payload));
  const user = claims.user_info || {};

  return {
    encoded: { header, payload, signature },
    header: JSON.parse(urlDecodeB64(header)),
    claims,
    user
  };
};

export const verify = (options: JWTVerifyOptions) => {
  if (!options.id_token) {
    throw new Error('ID token is required but missing');
  }

  const decoded = decode(options.id_token);
  // TODO 暂时只保留过期时间的校验
  const leeway = options.leeway || 60;
  const now = new Date(options.now || Date.now());
  const expDate = new Date(0);

  expDate.setUTCSeconds(decoded.claims.exp + leeway);

  if (now > expDate) {
    throw new Error(
      `Expiration Time (exp) claim error in the ID token; current time (${now}) is after expiration time (${expDate})`
    );
  }

  return decoded;
};
