import { GraphQLError } from 'graphql';

const CATEGORY_TECHNICAL = 'TECHNICAL';
const CATEGORY_BUSINESS = 'BUSINESS';

export const error = (type: string, message: string, data?: any) => {
  return new GraphQLError(message, { extensions: { code: type, data } });
};

const MUTED_ERROR = Symbol('mutedError');
type MuteableError = Error & { [MUTED_ERROR]?: boolean };
export const muteError = (e: MuteableError) => {
  e[MUTED_ERROR] = true;
  return e;
};

export const isMutedError = (e: MuteableError): boolean => e[MUTED_ERROR] === true;

// region TYPE_AUTH
export const AUTH_FAILURE = 'AUTH_FAILURE';
export const AuthenticationFailure = (reason?: string, data?: any) =>
  error(AUTH_FAILURE, reason || 'Bad login or password', {
    http_status: 401,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const AUTH_REQUIRED = 'AUTH_REQUIRED';
export const AuthRequired = (data?: any) =>
  error(AUTH_REQUIRED, 'You must be logged in to do this.', {
    http_status: 401,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const OTP_REQUIRED = 'OTP_REQUIRED';
export const OtpRequired = (data?: any) =>
  error(OTP_REQUIRED, 'You must validate your account with 2FA.', {
    http_status: 401,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED';
export const PasswordChangeRequired = (data?: any) =>
  error(PASSWORD_CHANGE_REQUIRED, 'You must change your password before continuing.', {
    http_status: 403,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const LTS_REQUIRED_ACTIVATION = 'LTS_REQUIRED_ACTIVATION';
export const LtsRequiredActivation = (data?: any) =>
  error(LTS_REQUIRED_ACTIVATION, 'You must activate your LTS license.', {
    http_status: 401,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const OTP_REQUIRED_ACTIVATION = 'OTP_REQUIRED_ACTIVATION';
export const OtpRequiredActivation = (data?: any) =>
  error(OTP_REQUIRED_ACTIVATION, 'You must activate your account with 2FA.', {
    http_status: 401,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const FORBIDDEN_ACCESS = 'FORBIDDEN_ACCESS';
export const ForbiddenAccess = (message?: string, data?: any) =>
  error(FORBIDDEN_ACCESS, message || 'You are not allowed to do this.', {
    http_status: 403,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const AUTH_ERRORS = [
  AUTH_FAILURE,
  AUTH_REQUIRED,
  OTP_REQUIRED,
  PASSWORD_CHANGE_REQUIRED,
  OTP_REQUIRED_ACTIVATION,
  FORBIDDEN_ACCESS,
];
// endregion

// region CATEGORY_TECHNICAL
export const DATABASE_ERROR = 'DATABASE_ERROR';
export const DatabaseError = (reason?: string, data?: any) =>
  error(DATABASE_ERROR, reason || 'A database error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

const FILESYSTEM_ERROR = 'FILESYSTEM_ERROR';
export const FilesystemError = (reason?: string, data?: any) => {
  return error(FILESYSTEM_ERROR, reason || 'A filesystem error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });
};

const COMPLEX_SEARCH_ERROR = 'COMPLEX_SEARCH_ERROR';
export const ComplexSearchError = (reason?: string, data?: any) =>
  error(COMPLEX_SEARCH_ERROR, reason || 'A search error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

const CONFIGURATION_ERROR = 'CONFIGURATION_ERROR';
export const ConfigurationError = (reason?: string, data?: any) =>
  error(CONFIGURATION_ERROR, reason || 'A configuration error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const UNKNOWN_ERROR = 'UNKNOWN_ERROR';
export const UnknownError = (reason?: string, data?: any) =>
  error(UNKNOWN_ERROR, reason || 'An unknown error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });

export const ACCESS_REQUIRED = 'ACCESS_REQUIRED';
export const AccessRequiredError = (reason?: string, data?: any) =>
  error(ACCESS_REQUIRED, reason || 'Access required', {
    http_status: 500,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const UNSUPPORTED_ERROR = 'UNSUPPORTED_ERROR';
export const UnsupportedError = (reason?: string, data?: any) =>
  error(UNSUPPORTED_ERROR, reason || 'Unsupported operation', {
    http_status: 500,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const EngineShardsError = (data?: any) =>
  error(
    DATABASE_ERROR,
    'Engine execution fail, some shards are not available, please check your engine status',
    {
      http_status: 500,
      genre: CATEGORY_BUSINESS,
      ...data,
    },
  );

// noinspection JSUnusedGlobalSymbols
export const TECHNICAL_ERRORS = [
  DATABASE_ERROR,
  FILESYSTEM_ERROR,
  COMPLEX_SEARCH_ERROR,
  CONFIGURATION_ERROR,
  UNKNOWN_ERROR,
  UNSUPPORTED_ERROR,
];
// endregion

// region CATEGORY_FUNCTIONAL
export const FUNCTIONAL_ERROR = 'FUNCTIONAL_ERROR';
export const INSUFFICIENT_CONFIDENCE_LEVEL = 'INSUFFICIENT_CONFIDENCE_LEVEL';
export const FunctionalError = (reason?: string, data?: any) =>
  error('FUNCTIONAL_ERROR', reason || 'Business validation', {
    http_status: 400,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const ALREADY_DELETED_ERROR = 'ALREADY_DELETED_ERROR';
export const AlreadyDeletedError = (data?: any) =>
  error(ALREADY_DELETED_ERROR, 'Already deleted elements', {
    http_status: 400,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const MISSING_REF_ERROR = 'MISSING_REFERENCE_ERROR';
export const MissingReferenceError = (data?: any) =>
  error(MISSING_REF_ERROR, 'Element(s) not found', {
    http_status: 404,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const VALIDATION_ERROR = 'VALIDATION_ERROR';
export const ValidationError = (message: string, field?: string | number, data?: any) =>
  error(VALIDATION_ERROR, message, {
    http_status: 500,
    genre: CATEGORY_BUSINESS,
    field,
    ...(data ?? {}),
  });

export const RESOURCE_NOT_FOUND_ERROR = 'RESOURCE_NOT_FOUND';
export const ResourceNotFoundError = (reason?: string, data?: any) =>
  error(RESOURCE_NOT_FOUND_ERROR, reason || 'Resource not found', {
    http_status: 404,
    ...data,
  });

const TYPE_LOCK = 'LOCK_ERROR';
export const TYPE_LOCK_ERROR = 'ExecutionError';
export const LockTimeoutError = (data: any, reason?: string) =>
  error(TYPE_LOCK, reason ?? 'Execution timeout, too many concurrent call on the same entities', {
    http_status: 500,
    genre: CATEGORY_BUSINESS,
    ...data,
  });

// Thrown when the caller (browser/proxy/connector) disconnects before an
// engine (e.g. Elasticsearch) call is even issued. This is NOT an engine
// failure: the engine is never reached, so it must not be logged/alerted on
// with the same severity as a real DATABASE_ERROR.
export const CLIENT_ABORT_ERROR = 'CLIENT_ABORT_ERROR';
export const ClientAbortError = (reason?: string, data?: any) =>
  error(CLIENT_ABORT_ERROR, reason || 'Client disconnected before the operation completed', {
    http_status: 499, // Conventionally used (nginx) for "Client Closed Request"
    genre: CATEGORY_BUSINESS,
    ...data,
  });

export const DRAFT_LOCKED_ERROR = 'DRAFT_LOCKED';
export const DraftLockedError = (reason?: string, data?: any) =>
  error(
    DRAFT_LOCKED_ERROR,
    reason ?? 'Draft is in a locked state, no request can be done within this draft',
    {
      http_status: 400,
      genre: CATEGORY_BUSINESS,
      ...data,
    },
  );

export const WORK_NOT_ALIVE_ERROR = 'WORK_NOT_ALIVE';
export const WorkNotALiveError = () =>
  error(
    WORK_NOT_ALIVE_ERROR,
    'Work is no longer alive, no request can be done within the context of this work',
    {
      http_status: 400,
      genre: CATEGORY_BUSINESS,
    },
  );

export const FUNCTIONAL_ERRORS = [
  FUNCTIONAL_ERROR,
  ALREADY_DELETED_ERROR,
  MISSING_REF_ERROR,
  VALIDATION_ERROR,
  RESOURCE_NOT_FOUND_ERROR,
  TYPE_LOCK_ERROR,
  CLIENT_ABORT_ERROR,
];
// endregion
