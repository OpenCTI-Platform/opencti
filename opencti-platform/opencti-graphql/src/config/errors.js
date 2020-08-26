import { createError } from 'apollo-errors';

const CATEGORY_TECHNICAL = 'technical';
const CATEGORY_BUSINESS = 'business';

const error = (type, message, data) => {
  const Exception = createError(type, { data, message });
  return new Exception();
};

export const AuthenticationFailure = (reason, data) =>
  error('AuthFailure', 'Wrong name or password', {
    category: CATEGORY_TECHNICAL,
    ...data,
  });

// TYPE_AUTH
export const AuthRequired = (reason, data) =>
  error('AuthRequired', 'You must be logged in to do this.', {
    category: CATEGORY_TECHNICAL,
    ...data,
  });

export const ForbiddenAccess = (reason, data) =>
  error('ForbiddenAccess', 'You are not allowed to do this.', {
    category: CATEGORY_TECHNICAL,
    ...data,
  });

// CATEGORY_TECHNICAL
export const DatabaseError = (reason, data) =>
  error('DatabaseError', 'A database error has occurred', {
    reason: reason || 'No reason specify',
    category: CATEGORY_TECHNICAL,
    ...data,
  });

export const ConfigurationError = (reason, data) =>
  error('ConfigurationError', 'A configuration error has occurred', {
    reason: reason || 'No reason specify',
    category: CATEGORY_TECHNICAL,
    ...data,
  });

export const UnknownError = (reason, data) =>
  error('UnknownError', 'An unknown error has occurred', {
    reason: reason || 'No reason specify',
    category: CATEGORY_TECHNICAL,
    ...data,
  });

const UNSUPPORTED_ERROR = 'UnsupportedError';
export const UnsupportedError = (reason, data) =>
  error(UNSUPPORTED_ERROR, 'Unsupported element', {
    reason: reason || 'No reason specify',
    category: CATEGORY_BUSINESS,
    ...data,
  });

export const FunctionalError = (reason, data) =>
  error('FunctionalError', 'Business validation', {
    reason: reason || 'No reason specify',
    category: CATEGORY_BUSINESS,
    ...data,
  });

export const TYPE_LOCK_ERROR = 'LockError';
export const TYPE_DUPLICATE_ENTRY = 'DuplicateEntryError';
export const DuplicateEntryError = (reason, data) =>
  error(TYPE_DUPLICATE_ENTRY, 'Existing element (Grakn)', {
    reason: reason || 'No reason specify',
    category: CATEGORY_BUSINESS,
    ...data,
  });

export const MissingReferenceError = (data) =>
  error('MissingReferenceError', 'Element not found', {
    reason: 'Missing reference to handle creation',
    category: CATEGORY_BUSINESS,
    ...data,
  });

export const ValidationError = (field, data) =>
  error('ValidationError', 'Validation error', {
    reason: `Invalid field ${field}`,
    category: CATEGORY_BUSINESS,
    ...data,
  });
