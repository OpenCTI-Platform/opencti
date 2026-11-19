// -- Local authentication lockout: the email to the administrators --
// When the final action locks an existing account, the administrators who can unlock it get an email.
// An unknown email never sends anything: there is no account to unlock.

import conf, { logApp } from '../config/conf';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../database/locked-user-email-template-input';
import type { LocalAuthLockType } from '../database/redis';
import { isNotEmptyField } from '../database/utils';
import { LocalAuthLockoutFinalAction } from '../generated/graphql';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { findLockedUserEmailTemplate } from '../modules/emailTemplate/emailTemplate-domain';
import type { LockedUserEmailData, LockedUserLock } from '../modules/emailTemplate/emailTemplate-render';
import { type EmailTemplateContent, sendEmailTemplateToRecipient } from '../modules/emailTemplate/emailTemplate-send';
import type { BasicStoreEntityOrganization } from '../modules/organization/organization-types';
import { type BasicStoreEntityUser, ENTITY_TYPE_USER } from '../modules/user/user-types';
import { LOCAL_AUTH_LOCKOUT_DEFAULTS } from './local-auth-lockout';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { isServiceAccountUser, isUserAccountActive, isUserHasCapability, SETTINGS_SETACCESSES, SYSTEM_USER } from '../utils/access';

// Same limit as the other emails sent to every administrator
const MAX_RECIPIENTS: number = conf.get('smtp:email_max_cc_size') || 500;

type LockRecipientsOptions = { withOrganizationAdmins: boolean; maxRecipients: number };

// Only an active account (neither expired nor with another status) with an email, never a service account.
// The locked user is left out: the email asks the administrators to check the lock, and to unlock the account if needed
const canReceiveLockEmail = (user: AuthUser, lockedUser: AuthUser) => user.id !== lockedUser.id
  && isUserAccountActive(user)
  && !isServiceAccountUser(user)
  && isNotEmptyField(user.user_email);

// The administrators of the accesses (SETTINGS_SETACCESSES, or BYPASS) can unlock any account. With the organization segregation,
// the administrators of an organization of the locked user can unlock it too: they come after the administrators of the accesses,
// so that the limit never leaves those out
export const selectLocalAuthLockRecipients = (platformUsers: AuthUser[], lockedUser: AuthUser, options: LockRecipientsOptions) => {
  const { withOrganizationAdmins, maxRecipients } = options;
  const candidates = platformUsers.filter((user) => canReceiveLockEmail(user, lockedUser));
  const accessAdministrators = candidates.filter((user) => isUserHasCapability(user, SETTINGS_SETACCESSES));
  const lockedUserOrganizationIds = new Set((lockedUser.organizations ?? []).map((organization) => organization.internal_id));
  const organizationAdministrators = withOrganizationAdmins
    ? candidates.filter((user) => !accessAdministrators.includes(user)
      && (user.administrated_organizations ?? []).some((organization) => lockedUserOrganizationIds.has(organization.internal_id)))
    : [];
  const recipients = [...accessAdministrators, ...organizationAdministrators];
  if (recipients.length > maxRecipients) {
    logApp.warn(`Local authentication lockout: too many administrators to tell about a lock, only the first ${maxRecipients} get the email`, {
      locked_user_id: lockedUser.id,
      recipients: recipients.length,
    });
    return recipients.slice(0, maxRecipients);
  }
  return recipients;
};

// The organization segregation is enabled when the settings hold a platform organization
export const loadLocalAuthLockRecipients = async (context: AuthContext, lockedUser: AuthUser) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const platformUsers = await getEntitiesListFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return selectLocalAuthLockRecipients(platformUsers, lockedUser, {
    withOrganizationAdmins: isNotEmptyField(settings.platform_organization),
    maxRecipients: MAX_RECIPIENTS,
  });
};

// The built-in template, as the administrators edited it. Once deleted, the email still goes with its default content
// until the next startup creates it again: a security alert must never be lost silently
export const loadLocalAuthLockEmailTemplate = async (context: AuthContext): Promise<EmailTemplateContent> => {
  const template = await findLockedUserEmailTemplate(context);
  if (template) {
    return template;
  }
  logApp.warn('Local authentication lockout: the built-in template for the locked users cannot be found, the email is sent with its default content', {
    template_name: LOCKED_USER_EMAIL_TEMPLATE_INPUT.name,
  });
  return LOCKED_USER_EMAIL_TEMPLATE_INPUT;
};

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

// One email per administrator, rendered for its recipient, never with an API token. Sent one after the other,
// as each send opens its own SMTP connection.
// A recipient whose email fails never stops the others. The failures are logged once, after the last send, as a warning:
// the SMTP server is an external dependency, and a down server must not log one error per administrator
export const sendLocalAuthLockEmails = async (context: AuthContext, lockedUser: AuthUser, lock: LocalAuthLock) => {
  const recipients = await loadLocalAuthLockRecipients(context, lockedUser);
  if (recipients.length === 0) {
    logApp.warn('Local authentication lockout: no administrator can get the email of a lock', { locked_user_id: lockedUser.id });
    return;
  }
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const template = await loadLocalAuthLockEmailTemplate(context);
  const lockedUserData = buildLocalAuthLockEmailData(lockedUser, lock);
  let errorsCount = 0;
  let firstError: unknown;
  for (const recipient of recipients) {
    try {
      // The user cache resolves the organizations of each user, with their name
      const organizations = recipient.organizations as BasicStoreEntityOrganization[];
      await sendEmailTemplateToRecipient(template, { ...recipient, organizations }, { platformUrl: settings.platform_url, category: 'local-auth-lock', lockedUserData });
    } catch (error) {
      errorsCount += 1;
      firstError ??= error;
    }
  }
  if (errorsCount > 0) {
    logApp.warn('Local authentication lockout: the email of a lock cannot be sent to some administrators', {
      cause: firstError,
      locked_user_id: lockedUser.id,
      errors_count: errorsCount,
      total_count: recipients.length,
    });
  }
};
