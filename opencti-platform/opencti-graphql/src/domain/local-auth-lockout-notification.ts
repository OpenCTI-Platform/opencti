// -- Local authentication lockout: the email to the administrators --
// When the final action locks an existing account, the administrators who can unlock it get an email.
// An unknown email never sends anything: there is no account to unlock.

import conf, { ACCOUNT_STATUS_ACTIVE, logApp } from '../config/conf';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { isNotEmptyField } from '../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { ENTITY_TYPE_USER } from '../modules/user/user-types';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { isServiceAccountUser, isUserHasCapability, SETTINGS_SETACCESSES, SYSTEM_USER } from '../utils/access';

// Same limit as the other emails sent to every administrator
const MAX_RECIPIENTS: number = conf.get('smtp:email_max_cc_size') || 500;

type LockRecipientsOptions = { withOrganizationAdmins: boolean; maxRecipients: number };

// Only an active account with an email, never a service account. The locked user is left out:
// the email asks the administrators to check the lock, and to unlock the account if needed
const canReceiveLockEmail = (user: AuthUser, lockedUser: AuthUser) => user.id !== lockedUser.id
  && user.account_status === ACCOUNT_STATUS_ACTIVE
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
