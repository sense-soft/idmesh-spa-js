export class GenericError extends Error {
  constructor(public error: string, public error_description: string) {
    super(error_description);
    Object.setPrototypeOf(this, GenericError.prototype);
  }

  static fromPayload({
    error,
    error_description
  }: {
    error: string;
    error_description: string;
  }) {
    return new GenericError(error, error_description);
  }
}

export class AuthenticationError extends GenericError {
  constructor(
    error: string,
    error_description: string,
    public state: string,
    public appState: any = null
  ) {
    super(error, error_description);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class TimeoutError extends GenericError {
  constructor() {
    super('timeout', 'Timeout');
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

export class PopupTimeoutError extends TimeoutError {
  constructor(public popup: Window) {
    super();
    Object.setPrototypeOf(this, PopupTimeoutError.prototype);
  }
}

export class PopupCancelledError extends GenericError {
  constructor(public popup: Window) {
    super('cancelled', 'Popup closed');
    Object.setPrototypeOf(this, PopupCancelledError.prototype);
  }
}

export class MfaRequiredError extends GenericError {
  constructor(
    error: string,
    error_description: string,
    public mfa_token: string
  ) {
    super(error, error_description);
    Object.setPrototypeOf(this, MfaRequiredError.prototype);
  }
}

export class MissingRefreshTokenError extends GenericError {
  constructor(public audience: string, public scope: string) {
    super(
      'missing_refresh_token',
      `Missing Refresh Token (audience: '${valueOrEmptyString(audience, [
        'default'
      ])}', scope: '${valueOrEmptyString(scope)}')`
    );
    Object.setPrototypeOf(this, MissingRefreshTokenError.prototype);
  }
}

function valueOrEmptyString(value: string, exclude: string[] = []) {
  return value && !exclude.includes(value) ? value : '';
}
