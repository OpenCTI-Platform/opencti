// Sentinel stored as a custom field's default_value (date type only) meaning "resolve to the
// current date/time when the field gets populated", instead of a fixed ISO date/time string.
export const CUSTOM_FIELD_NOW_TOKEN = '@now';

// Resolves a custom field's raw default_value into the value usable to prefill a form:
// the @now token becomes the current date/time, anything else (including null) is returned as-is.
export const resolveCustomFieldDefaultValue = (defaultValue: string | null | undefined): string | null => {
  if (defaultValue === CUSTOM_FIELD_NOW_TOKEN) {
    return new Date().toISOString();
  }
  return defaultValue ?? null;
};
