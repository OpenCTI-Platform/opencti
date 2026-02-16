import { providerLoginHandler } from './providers-configuration';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { getSettings } from '../../domain/settings';
import { forgetPromise } from '../../utils/promiseUtils';
import { type AuthenticationProviderLogger } from './providers-logger';
import { createMappers } from './mappings-utils';

export const createHeaderLoginHandler = (logger: AuthenticationProviderLogger, context: AuthContext) => async (req: any) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const headerStrategy = settings.headers_auth;
  if (!headerStrategy) {
    return null;
  }

  logger.info('Processing login request');

  const { resolveUserInfo, resolveGroups, resolveOrganizations } = createMappers(headerStrategy);
  const headerResolver = (expr: string) => req.headers[expr.toLowerCase()];
  const userInfo = await resolveUserInfo(headerResolver);
  const groups = await resolveGroups(headerResolver);
  const organizations = await resolveOrganizations(headerResolver);

  logger.info('User info resolved', { userInfo, groups, organizations });

  const provider_metadata = { headers_audit: headerStrategy.headers_audit };
  return new Promise((resolve, reject) => {
    const done = (err: any, user: any) => {
      if (err) {
        reject(err);
      } else {
        resolve(user);
      }
    };
    forgetPromise(providerLoginHandler(
      { ...userInfo, provider_metadata },
      done,
      {
        providerGroups: groups,
        providerOrganizations: organizations,
        autoCreateGroup: headerStrategy.groups_mapping.auto_create_groups,
        preventDefaultGroups: headerStrategy.groups_mapping.prevent_default_groups,
      },
    ));
  });
};
