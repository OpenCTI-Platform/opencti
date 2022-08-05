import { createError } from 'apollo-errors';

const CATEGORY_TECHNICAL = 'technical';
const CATEGORY_BUSINESS = 'business';

const error = (type, message, data) => {
  const Exception = createError(type, { data, message });
  return new Exception();
};

export const AUTH_FAILURE = 'AuthFailure';
export const AuthenticationFailure = (reason, data) => error(AUTH_FAILURE, reason || 'Wrong name or password', {
  http_status: 401,
  category: CATEGORY_TECHNICAL,
  ...data,
});

// TYPE_AUTH
export const AUTH_REQUIRED = 'AuthRequired';
export const AuthRequired = (data) => error(AUTH_REQUIRED, 'You must be logged in to do this.', {
  http_status: 401,
  category: CATEGORY_TECHNICAL,
  ...data,
});

export const OTP_REQUIRED = 'OtpRequired';
export const OtpRequired = (data) => error(OTP_REQUIRED, 'You must validate your accout with 2FA.', {
  http_status: 401,
  category: CATEGORY_TECHNICAL,
  ...data,
});

export const FORBIDDEN_ACCESS = 'ForbiddenAccess';
export const ForbiddenAccess = (data) => error(FORBIDDEN_ACCESS, 'You are not allowed to do this.', {
  http_status: 403,
  category: CATEGORY_TECHNICAL,
  ...data,
});

const RESOURCE_NOT_FOUND_ERROR = 'ResourceNotFound';
export const ResourceNotFoundError = (data) => error(RESOURCE_NOT_FOUND_ERROR, 'Resource not found', {
  http_status: 404,
  ...data,
});

// CATEGORY_TECHNICAL
export const DatabaseError = (reason, data) => error('DatabaseError', 'A database error has occurred', {
  reason: reason || 'No reason specify',
  http_status: 500,
  category: CATEGORY_TECHNICAL,
  ...data,
});

export const ConfigurationError = (reason, data) => error('ConfigurationError', 'A configuration error has occurred', {
  reason: reason || 'No reason specify',
  http_status: 500,
  category: CATEGORY_TECHNICAL,
  ...data,
});

export const UnknownError = (reason, data) => error('UnknownError', 'An unknown error has occurred', {
  reason: reason || 'No reason specify',
  http_status: 500,
  category: CATEGORY_TECHNICAL,
  ...data,
});

export const UNSUPPORTED_ERROR = 'UnsupportedError';
export const UnsupportedError = (reason, data) => error(UNSUPPORTED_ERROR, 'Unsupported operation', {
  reason: reason || 'No reason specify',
  http_status: 500,
  category: CATEGORY_BUSINESS,
  ...data,
});

export const FunctionalError = (reason, data) => error('FunctionalError', 'Business validation', {
  reason: reason || 'No reason specify',
  http_status: 400,
  category: CATEGORY_BUSINESS,
  ...data,
});

export const TYPE_LOCK_ERROR = 'ExecutionError';
export const LockTimeoutError = (data, reason) => error('LockError', 'Lock timeout', {
  reason: reason ?? 'Execution timeout, too many concurrent call on the same entities',
  http_status: 500,
  category: CATEGORY_BUSINESS,
  ...data,
});

export const TYPE_DUPLICATE_ENTRY = 'DuplicateEntryError';
export const DuplicateEntryError = (reason, data) => error(TYPE_DUPLICATE_ENTRY, 'Existing element', {
  reason: reason || 'No reason specify',
  http_status: 500,
  category: CATEGORY_BUSINESS,
  ...data,
});

export const MISSING_REF_ERROR = 'MissingReferenceError';
export const MissingReferenceError = (data) => error(MISSING_REF_ERROR, 'Element not found', {
  reason: 'Missing reference to handle creation',
  http_status: 404,
  category: CATEGORY_BUSINESS,
  ...data,
});

export const ValidationError = (field, data) => error('ValidationError', 'Validation error', {
  reason: `Invalid field ${field}`,
  http_status: 500,
  category: CATEGORY_BUSINESS,
  field,
  ...data,
});
