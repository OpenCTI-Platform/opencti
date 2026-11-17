// The data the back end adds to a refused local login once the local authentication lockout has locked the account
export interface LocalAuthLockErrorData {
  lock?: 'temporary' | 'permanent';
  remaining_minutes?: number;
}

export interface LocalAuthLockError {
  message?: string;
  extensions?: { data?: LocalAuthLockErrorData };
}

type Translate = (message: string, options?: { values: Record<string, number> }) => string;

const MINUTES_PER_HOUR = 60;

// The message to show for a locked account, or undefined when the error is not a lock.
// A temporary lock shows its remaining time, rounded up: in minutes, then in hours from 60 minutes on, as it lasts up to a day.
// A permanent lock shows the message of the Locked account status, sent by the back end
export const localAuthLockMessage = (t_i18n: Translate, error?: LocalAuthLockError): string | undefined => {
  const data = error?.extensions?.data;
  if (data?.lock === 'permanent') {
    return t_i18n(error?.message ?? 'Your account has been locked for security reasons. Please contact your administrator.');
  }
  if (data?.lock === 'temporary' && data.remaining_minutes !== undefined) {
    const minutes = data.remaining_minutes;
    if (minutes < MINUTES_PER_HOUR) {
      return t_i18n('Your account has been locked for security reasons. Please try again in {minutes, plural, one {# minute} other {# minutes}}.', { values: { minutes } });
    }
    const hours = Math.ceil(minutes / MINUTES_PER_HOUR);
    return t_i18n('Your account has been locked for security reasons. Please try again in {hours, plural, one {# hour} other {# hours}}.', { values: { hours } });
  }
  return undefined;
};

// The same, for a refused mutation: reads its first error
export const relayLocalAuthLockMessage = (t_i18n: Translate, error: unknown): string | undefined => {
  const firstError = (error as { res?: { errors?: LocalAuthLockError[] } } | undefined)?.res?.errors?.[0];
  return localAuthLockMessage(t_i18n, firstError);
};
