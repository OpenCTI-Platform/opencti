import { RelayError } from '../relay/relayTypes';

export const PASSWORD_REUSED = 'PASSWORD_REUSED';
export const PASSWORD_CHANGE_THROTTLED = 'PASSWORD_CHANGE_THROTTLED';
export const PASSWORD_RESET_EXPIRED = 'PASSWORD_RESET_EXPIRED';

const PASSWORD_CHANGE_ERROR_CODES = [PASSWORD_REUSED, PASSWORD_CHANGE_THROTTLED, PASSWORD_RESET_EXPIRED];

// The code of a refused password change the screens explain on their own, if any
export const passwordChangeErrorCode = (error: unknown): string | undefined => {
  const errors = (error as RelayError | undefined)?.res?.errors ?? [];
  const found = errors.find((e) => PASSWORD_CHANGE_ERROR_CODES.includes(e?.extensions?.code ?? e?.name ?? ''));
  return found ? (found.extensions?.code ?? found.name) : undefined;
};

export const passwordChangeErrorMessages = (t_i18n: (message: string) => string): Record<string, string> => ({
  [PASSWORD_REUSED]: t_i18n('This password has already been used recently. Please choose a different one.'),
  [PASSWORD_CHANGE_THROTTLED]: t_i18n('Too many password change attempts. Please try again in a few minutes.'),
  [PASSWORD_RESET_EXPIRED]: t_i18n('Password reset code expired or not found. Please request a new one.'),
});

// The Formik helpers it needs, whatever the values of the form
interface PasswordFormHelpers {
  setFieldValue: (field: string, value: string, shouldValidate?: boolean) => unknown;
  setFieldTouched: (field: string, isTouched?: boolean, shouldValidate?: boolean) => unknown;
  setFieldError: (field: string, message: string | undefined) => void;
}

// Clears the typed passwords and says why under the new password field. Not with resetForm(nextState): it makes that state
// the starting one of the form, so the resetForm() of a later successful change would bring the error back.
// The other cleared fields go back to untouched: the submit touched them, and once emptied they would show
// "This field is required" as soon as the user types in the new password field
export const showPasswordFieldError = (helpers: PasswordFormHelpers, message: string, passwordField: string, clearedFields: string[]) => {
  clearedFields.forEach((field) => {
    helpers.setFieldValue(field, '', false);
    helpers.setFieldTouched(field, field === passwordField, false);
  });
  helpers.setFieldError(passwordField, message);
};
