const ONE_SECOND = 1000;
const ONE_MINUTE = 60 * ONE_SECOND;
const ONE_HOUR = 60 * ONE_MINUTE;
const ONE_DAY = 24 * ONE_HOUR;

const UNITS = [
  { duration: ONE_DAY, one: 'day', many: 'days' },
  { duration: ONE_HOUR, one: 'hour', many: 'hours' },
  { duration: ONE_MINUTE, one: 'minute', many: 'minutes' },
  { duration: ONE_SECOND, one: 'second', many: 'seconds' },
];

/**
 * Text of the maximum lifetime of a session (app:session_max_lifetime, in ms), as shown in the authentication settings.
 * The value comes from the platform configuration and must be shown exactly: it is written in the largest unit
 * it is a whole number of (7 days, 12 hours, 90 seconds), in seconds otherwise (1.5 seconds), never rounded.
 */
export const formatSessionMaxLifetime = (maxLifetime: number, t_i18n: (key: string) => string) => {
  if (maxLifetime <= 0) {
    return t_i18n('Unlimited');
  }
  const unit = UNITS.find(({ duration }) => maxLifetime % duration === 0);
  if (unit) {
    const value = maxLifetime / unit.duration;
    return `${value} ${t_i18n(value === 1 ? unit.one : unit.many)}`;
  }
  return `${maxLifetime / ONE_SECOND} ${t_i18n('seconds')}`;
};
