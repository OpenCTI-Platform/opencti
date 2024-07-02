import { GraphQLError } from 'graphql/index';

const CATEGORY_TECHNICAL = 'TECHNICAL';
const CATEGORY_BUSINESS = 'BUSINESS';

const error = (type, message, data) => {
  return new GraphQLError(message, { extensions: { code: type, name: type, data } });
};

export const AUTH_FAILURE = 'AUTH_FAILURE';
export const AuthenticationFailure = (reason, data) => error(AUTH_FAILURE, reason || 'Bad login or password', {
  http_status: 401,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

// TYPE_AUTH
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
  }
);

const RESOURCE_NOT_FOUND_ERROR = 'RESOURCE_NOT_FOUND';
export const ResourceNotFoundError = (data) => error(RESOURCE_NOT_FOUND_ERROR, 'Resource not found', {
  http_status: 404,
  ...data,
});

// CATEGORY_TECHNICAL
export const DatabaseError = (reason, data) => error('DATABASE_ERROR', reason || 'A database error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const FilesystemError = (reason, data) => error('FILESYSTEM_ERROR', reason || 'A filesystem error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const ComplexSearchError = (reason, data) => error('COMPLEX_SEARCH_ERROR', reason || 'A search error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const ConfigurationError = (reason, data) => error('CONFIGURATION_ERROR', reason || 'A configuration error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const UnknownError = (reason, data) => error('UNKNOWN_ERROR', reason || 'An unknown error has occurred', {
  http_status: 500,
  genre: CATEGORY_TECHNICAL,
  ...data,
});

export const UNSUPPORTED_ERROR = 'UNSUPPORTED_ERROR';
export const UnsupportedError = (reason, data) => error(UNSUPPORTED_ERROR, reason || 'Unsupported operation', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

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

const TYPE_LOCK = 'LOCK_ERROR';
export const TYPE_LOCK_ERROR = 'ExecutionError';
export const LockTimeoutError = (data, reason) => error(TYPE_LOCK, reason ?? 'Execution timeout, too many concurrent call on the same entities', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  ...data,
});

export const EngineShardsError = (data) => error('DATABASE_ERROR', 'Engine execution fail, some shards are not available, please check your engine status', {
  http_status: 500,
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
export const ValidationError = (field, data) => error(VALIDATION_ERROR, 'Validation error', {
  http_status: 500,
  genre: CATEGORY_BUSINESS,
  field,
  ...data,
});
