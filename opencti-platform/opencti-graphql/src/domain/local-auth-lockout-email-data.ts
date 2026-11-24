// -- Local authentication lockout: the data of the lock email --
// The $locked_user and $lock variables of the email sent to the administrators, for a real lock or for the example lock
// of the "Send test email" button. Imports neither the lockout nor the email templates, so that both can use it

import type { LocalAuthLockType } from '../database/redis';
import { LocalAuthLockoutFinalAction } from '../generated/graphql';
import type { LockedUserEmailData, LockedUserLock } from '../modules/emailTemplate/emailTemplate-render';
import type { BasicStoreEntityUser } from '../modules/user/user-types';
import type { BasicStoreSettings } from '../types/settings';
import { LOCAL_AUTH_LOCKOUT_DEFAULTS } from './local-auth-lockout-defaults';

// The lock set by the attempt that reached the max attempts: its final action, when it was set, and the time it lasts
// from then (the lockout duration). Its date is the one of the lock, not of the email: the email is sent later, in the background
export type LocalAuthLock = { lockType: LocalAuthLockType; maxAttempts: number; date: Date; remainingMs: number };
type LockedAccount = Pick<BasicStoreEntityUser, 'name' | 'user_email'> & Partial<Pick<BasicStoreEntityUser, 'firstname' | 'lastname'>>;

// The data of the $locked_user and $lock variables. Only the attempt that reaches the max attempts locks the account,
// so the attempts are the max attempts. A temporary lock ends after the lockout duration, a permanent lock has no end:
// an administrator must unlock the account
export const buildLocalAuthLockEmailData = (lockedUser: LockedAccount, { lockType, maxAttempts, date, remainingMs }: LocalAuthLock): LockedUserEmailData => {
  const { name, firstname, lastname, user_email } = lockedUser;
  const lock: LockedUserLock = lockType === 'temporary'
    ? { date, attempts: maxAttempts, type: 'temporary', endDate: new Date(date.getTime() + remainingMs) }
    : { date, attempts: maxAttempts, type: 'permanent' };
  return { lockedUser: { name, firstname, lastname, user_email }, lock };
};

// The example account of the "Send test email" button of a template
const SAMPLE_LOCKED_USER = { name: 'jdoe', firstname: 'John', lastname: 'Doe', user_email: 'john.doe@example.com' };
type LockoutPolicySettings = Partial<Pick<BasicStoreSettings, 'local_auth_lockout_final_action' | 'local_auth_lockout_max_attempts' | 'local_auth_lockout_duration'>>;

// The $locked_user and $lock variables of the "Send test email" button: an example lock that follows the lockout policy of the platform,
// its final action, the max attempts of the users and the lockout duration
export const buildSampleLocalAuthLockEmailData = (settings: LockoutPolicySettings, date = new Date()): LockedUserEmailData => {
  const finalAction = settings.local_auth_lockout_final_action ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_final_action;
  const maxAttempts = settings.local_auth_lockout_max_attempts ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_attempts;
  const durationMinutes = settings.local_auth_lockout_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_duration;
  const lockType = finalAction === LocalAuthLockoutFinalAction.Permanent ? 'permanent' : 'temporary';
  return buildLocalAuthLockEmailData(SAMPLE_LOCKED_USER, { lockType, maxAttempts, date, remainingMs: durationMinutes * 60 * 1000 });
};
