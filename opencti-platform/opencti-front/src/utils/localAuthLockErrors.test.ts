import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import { localAuthLockMessage } from './localAuthLockErrors';
import en from '../../lang/front/en.json';
import fr from '../../lang/front/fr.json';

const LOCKED_MESSAGE = 'Your account has been locked for security reasons. Please contact your administrator.';

// Translates as the t_i18n of the application: a message missing from the translations is shown as is
const translator = (locale: string, messages: Record<string, string>) => {
  const intl = createIntl({ locale, messages, defaultLocale: 'en', onError: () => {} });
  return (message: string, options?: { values: Record<string, number> }) => intl.formatMessage({ id: message, defaultMessage: message }, options?.values);
};
const t_en = translator('en', en);
const t_fr = translator('fr', fr);

const temporaryLock = (minutes: number) => ({ message: 'Your account has been locked for security reasons. Please try again later.', extensions: { data: { lock: 'temporary' as const, remaining_minutes: minutes } } });

describe('localAuthLockMessage', () => {
  it('shows the remaining minutes of a temporary lock, singular and plural', () => {
    expect(localAuthLockMessage(t_en, temporaryLock(1))).toBe('Your account has been locked for security reasons. Please try again in 1 minute.');
    expect(localAuthLockMessage(t_en, temporaryLock(59))).toBe('Your account has been locked for security reasons. Please try again in 59 minutes.');
  });

  it('shows hours from 60 minutes on, rounded up', () => {
    expect(localAuthLockMessage(t_en, temporaryLock(60))).toBe('Your account has been locked for security reasons. Please try again in 1 hour.');
    expect(localAuthLockMessage(t_en, temporaryLock(61))).toBe('Your account has been locked for security reasons. Please try again in 2 hours.');
    expect(localAuthLockMessage(t_en, temporaryLock(1440))).toBe('Your account has been locked for security reasons. Please try again in 24 hours.');
  });

  it('translates the remaining time', () => {
    expect(localAuthLockMessage(t_fr, temporaryLock(1))).toBe('Votre compte a été verrouillé pour des raisons de sécurité. Veuillez réessayer dans 1 minute.');
    expect(localAuthLockMessage(t_fr, temporaryLock(120))).toBe('Votre compte a été verrouillé pour des raisons de sécurité. Veuillez réessayer dans 2 heures.');
  });

  it('shows the message of the Locked status for a permanent lock, translated', () => {
    const permanentLock = { message: LOCKED_MESSAGE, extensions: { data: { lock: 'permanent' as const } } };
    expect(localAuthLockMessage(t_en, permanentLock)).toBe(LOCKED_MESSAGE);
    expect(localAuthLockMessage(t_fr, permanentLock)).toBe('Votre compte a été verrouillé pour des raisons de sécurité. Veuillez contacter votre administrateur.');
  });

  it('keeps a Locked message customized in the configuration', () => {
    const customized = { message: 'Locked: call the help desk.', extensions: { data: { lock: 'permanent' as const } } };
    expect(localAuthLockMessage(t_fr, customized)).toBe('Locked: call the help desk.');
  });

  it('returns nothing when the error is not a lock', () => {
    expect(localAuthLockMessage(t_en, { message: 'Bad login or password' })).toBeUndefined();
    expect(localAuthLockMessage(t_en, { message: 'x', extensions: { data: {} } })).toBeUndefined();
    expect(localAuthLockMessage(t_en, undefined)).toBeUndefined();
  });

  it('has a translation of each lock message in every language', async () => {
    const keys = [
      LOCKED_MESSAGE,
      'Your account has been locked for security reasons. Please try again in {minutes, plural, one {# minute} other {# minutes}}.',
      'Your account has been locked for security reasons. Please try again in {hours, plural, one {# hour} other {# hours}}.',
    ];
    for (const lang of ['de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'ru', 'zh']) {
      const translations = (await import(`../../lang/front/${lang}.json`)).default as Record<string, string>;
      keys.forEach((key) => expect(translations[key], `${lang}: ${key}`).toBeTruthy());
    }
  });
});
