/**
 * Marks the external references that resolvePendingFieldRefs (form-pending.ts) produced from the
 * pool of objects created on submission. The direct external reference fields only accept these
 * objects: any other object sent by the client is rejected. Kept in its own module so the field
 * converter can use it without importing form-pending.
 */
export const PENDING_EXTERNAL_REFERENCE = Symbol('form-pending-external-reference');
