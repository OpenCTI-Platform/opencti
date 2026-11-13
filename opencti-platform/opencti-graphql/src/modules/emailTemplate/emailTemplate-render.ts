import { DateTime } from 'luxon';
import { isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../../config/conf';
import { safeRender } from '../../utils/safeEjs.client';
import { sanitizeUser } from '../../utils/templateContextSanitizer';

// The account locked by the local authentication lockout, and its lock, for the email sent to the administrators
export type LockedUserEmailData = {
  lockedUser: { name: string; firstname?: string; lastname?: string; user_email: string };
  // attempts: the failed authentication attempts that locked the account. endDate: only for a temporary lock
  lock: { date: Date; attempts: number; type: 'temporary' | 'permanent'; endDate?: Date };
};

export type EmailTemplateData = {
  platformUrl: string;
  // The recipient
  user: Record<string, unknown>;
  organizationNames: string[];
  lockedUserData?: LockedUserEmailData;
};

// The variables an email template can use, and their value in the rendering
const RECIPIENT_VARIABLES: [string, string][] = [
  ['$user.firstname', '<%= user.firstname %>'],
  ['$user.lastname', '<%= user.lastname %>'],
  ['$user.name', '<%= user.name %>'],
  ['$user.user_email', '<%= user.user_email %>'],
  ['$user.api_token', '<%= user.api_token %>'],
  ['$user.account_status', '<%= user.account_status %>'],
  ['$user.objectOrganization', '<%= organizationNames.join(", ") %>'],
  ['$user.account_lock_after_date', '<%= user.account_lock_after_date %>'],
  ['$settings.platform_url', '<%= platformUrl %>'],
];
// Only behind the feature flag of the local authentication lockout: without it, they stay as written
const LOCK_VARIABLES: [string, string][] = [
  ['$locked_user.firstname', '<%= locked_user.firstname %>'],
  ['$locked_user.lastname', '<%= locked_user.lastname %>'],
  ['$locked_user.name', '<%= locked_user.name %>'],
  ['$locked_user.user_email', '<%= locked_user.user_email %>'],
  ['$lock.date', '<%= lock.date %>'],
  ['$lock.attempts', '<%= lock.attempts %>'],
  ['$lock.type', '<%= lock.type %>'],
  ['$lock.end_date', '<%= lock.end_date %>'],
  ['$lock.unlock', '<%= lock.unlock %>'],
];

export const preprocessEmailTemplate = (templateBody: string) => {
  const variables = isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG) ? [...RECIPIENT_VARIABLES, ...LOCK_VARIABLES] : RECIPIENT_VARIABLES;
  return variables.reduce((body, [variable, value]) => body.split(variable).join(value), templateBody);
};

const formatLockDate = (date: Date) => DateTime.fromJSDate(date, { zone: 'utc' }).toFormat('yyyy-MM-dd HH:mm \'UTC\'');

// A template has no condition: $lock.unlock is the sentence that fits the lock, the end of a temporary lock,
// or the administrator who must unlock a permanent one. Without a lock (a test email for example), every lock variable is empty
const buildLockData = (lockedUserData?: LockedUserEmailData) => {
  if (!lockedUserData) {
    return {
      locked_user: { name: '', firstname: '', lastname: '', user_email: '' },
      lock: { date: '', attempts: '', type: '', end_date: '', unlock: '' },
    };
  }
  const { lockedUser, lock } = lockedUserData;
  const { name, firstname, lastname, user_email } = sanitizeUser(lockedUser);
  const endDate = lock.type === 'temporary' && lock.endDate ? formatLockDate(lock.endDate) : '';
  return {
    locked_user: { name: name ?? '', firstname: firstname ?? '', lastname: lastname ?? '', user_email: user_email ?? '' },
    lock: {
      date: formatLockDate(lock.date),
      attempts: String(lock.attempts),
      type: lock.type,
      end_date: endDate,
      unlock: lock.type === 'permanent'
        ? 'The account is locked until an administrator unlocks it.'
        : `The account is locked until ${endDate}.`,
    },
  };
};

export const renderEmailTemplate = (templateBody: string, { platformUrl, user, organizationNames, lockedUserData }: EmailTemplateData) => {
  return safeRender(preprocessEmailTemplate(templateBody), {
    platformUrl,
    user,
    organizationNames,
    ...buildLockData(lockedUserData),
  });
};
