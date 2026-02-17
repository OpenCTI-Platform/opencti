import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { getSettings } from '../../domain/settings';
import { forgetPromise } from '../../utils/promiseUtils';
import { type AuthenticationProviderLogger } from './providers-logger';
import { createMapper } from './mappings-utils';
import { handleProviderLogin } from './providers';
import { ForbiddenAccess } from '../../config/errors';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';

export const createHeaderLoginHandler = (logger: AuthenticationProviderLogger, context: AuthContext) => async (req: any) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const headerStrategy = settings.headers_auth;
  if (!headerStrategy) {
    return undefined;
  }

  if (!await isEnterpriseEdition(context)) {
    throw ForbiddenAccess('Header authentication strategy is only available with a valid Enterprise Edition license');
  }

  logger.info('Processing login request');

  const resolveExpr = (expr: string) => (obj: unknown) => {
    const headers = obj as Record<string, string>;
    return headers[expr.toLowerCase()];
  };
  const mapper = createMapper(headerStrategy, resolveExpr);
  const providerLoginInfo = await mapper(req.headers);
  const infoWithMeta = {
    ...providerLoginInfo,
    userMapping: {
      ...providerLoginInfo.userMapping,
      provider_metadata: { headers_audit: headerStrategy.headers_audit },
    },
  };

  return new Promise((resolve, reject) => {
    const done = (err: any, user: any) => {
      if (err) {
        reject(err);
      } else {
        resolve(user);
      }
    };
    forgetPromise(handleProviderLogin(logger, infoWithMeta, done));
  });
};
