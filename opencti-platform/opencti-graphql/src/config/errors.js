import { GraphQLError } from 'graphql/index';

const CATEGORY_TECHNICAL = 'TECHNICAL';
const CATEGORY_BUSINESS = 'BUSINESS';

export const error = (type, message, data) => {
  return new GraphQLError(message, { extensions: { code: type, data } });
};

const MUTED_ERROR = Symbol('mutedError');
export const muteError = (e) => {
  e[MUTED_ERROR] = true;
  return e;
};

export const isMutedError = (e) => e[MUTED_ERROR];

// region TYPE_AUTH
export const AUTH_FAILURE = 'AUTH_FAILURE';
export const AuthenticationFailure = (reason, data) => error(AUTH_FAILURE, reason || 'Bad login or password', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const AUTH_REQUIRED = 'AUTH_REQUIRED';
export const AuthRequired = (data) => error(AUTH_REQUIRED, 'You must be logged in to do this.', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const OTP_REQUIRED = 'OTP_REQUIRED';
export const OtpRequired = (data) => error(OTP_REQUIRED, 'You must validate your account with 2FA.', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const LTS_REQUIRED_ACTIVATION = 'LTS_REQUIRED_ACTIVATION';
export const LtsRequiredActivation = (data) => error(LTS_REQUIRED_ACTIVATION, 'You must activate your LTS license.', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const OTP_REQUIRED_ACTIVATION = 'OTP_REQUIRED_ACTIVATION';
export const OtpRequiredActivation = (data) => error(OTP_REQUIRED_ACTIVATION, 'You must activate your account with 2FA.', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const FORBIDDEN_ACCESS = 'FORBIDDEN_ACCESS';
export const ForbiddenAccess = (message, data) => error(
  FORBIDDEN_ACCESS,
  message || 'You are not allowed to do this.',
  {
    http_status: 403,
    genre: CATEGORY_TECHNICAL,
    ...data,
  },
);

export const AUTH_ERRORS = [
  AUTH_FAILURE,
  AUTH_REQUIRED,
  OTP_REQUIRED,
  OTP_REQUIRED_ACTIVATION,
  FORBIDDEN_ACCESS,
];
// endregion

// region CATEGORY_TECHNICAL
const DATABASE_ERROR = 'DATABASE_ERROR';
export const DatabaseError = (reason, data) => error(DATABASE_ERROR, reason || 'A database error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

const FILESYSTEM_ERROR = 'FILESYSTEM_ERROR';
export const FilesystemError = (reason, data) => {
  return error(FILESYSTEM_ERROR, reason || 'A filesystem error has occurred', {
    http_status: 500,
    genre: CATEGORY_TECHNICAL,
    ...data,
  });
};

const COMPLEX_SEARCH_ERROR = 'COMPLEX_SEARCH_ERROR';
export const ComplexSearchError = (reason, data) => error(COMPLEX_SEARCH_ERROR, reason || 'A search error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

const CONFIGURATION_ERROR = 'CONFIGURATION_ERROR';
export const ConfigurationError = (reason, data) => error(CONFIGURATION_ERROR, reason || 'A configuration error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const UNKNOWN_ERROR = 'UNKNOWN_ERROR';
export const UnknownError = (reason, data) => error(UNKNOWN_ERROR, reason || 'An unknown error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const ACCESS_REQUIRED = 'ACCESS_REQUIRED';
export const AccessRequiredError = (reason, data) => error(ACCESS_REQUIRED, reason || 'Access required', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const UNSUPPORTED_ERROR = 'UNSUPPORTED_ERROR';
export const UnsupportedError = (reason, data) => error(UNSUPPORTED_ERROR, reason || 'Unsupported operation', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const EngineShardsError = (data) => error(DATABASE_ERROR, 'Engine execution fail, some shards are not available, please check your engine status', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

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
export const FunctionalError = (reason, data) => error('FUNCTIONAL_ERROR', reason || 'Business validation', {
  http_status: 400,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const ALREADY_DELETED_ERROR = 'ALREADY_DELETED_ERROR';
export const AlreadyDeletedError = (data) => error(ALREADY_DELETED_ERROR, 'Already deleted elements', {
  http_status: 400,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const MISSING_REF_ERROR = 'MISSING_REFERENCE_ERROR';
export const MissingReferenceError = (data) => error(MISSING_REF_ERROR, 'Element(s) not found', {
  http_status: 404,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const VALIDATION_ERROR = 'VALIDATION_ERROR';
export const ValidationError = (message, field, data) => error(VALIDATION_ERROR, message, {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  field,
  ...(data ?? {}),
});

export const RESOURCE_NOT_FOUND_ERROR = 'RESOURCE_NOT_FOUND';
export const ResourceNotFoundError = (reason, data) => error(RESOURCE_NOT_FOUND_ERROR, reason || 'Resource not found', {
  http_status: 404,
  ...data,
});

const TYPE_LOCK = 'LOCK_ERROR';
export const TYPE_LOCK_ERROR = 'ExecutionError';
export const LockTimeoutError = (data, reason) => error(TYPE_LOCK, reason ?? 'Execution timeout, too many concurrent call on the same entities', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const DRAFT_LOCKED_ERROR = 'DRAFT_LOCKED';
export const DraftLockedError = (data) => error(DRAFT_LOCKED_ERROR, 'Draft is in a locked state, no request can be done within this draft', {
  http_status: 400,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const FUNCTIONAL_ERRORS = [
  FUNCTIONAL_ERROR,
  ALREADY_DELETED_ERROR,
  MISSING_REF_ERROR,
  VALIDATION_ERROR,
  RESOURCE_NOT_FOUND_ERROR,
  TYPE_LOCK_ERROR,
];
// endregion
