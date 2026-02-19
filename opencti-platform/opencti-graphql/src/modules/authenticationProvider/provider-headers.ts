import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { getSettings } from '../../domain/settings';
import { type AuthenticationProviderLogger, createAuthLogger } from './providers-logger';
import { createMapper } from './mappings-utils';
import { handleProviderLogin } from './providers';
import { ForbiddenAccess } from '../../config/errors';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { AuthType, EnvStrategyType, HEADERS_STRATEGY_IDENTIFIER, type ProviderConfiguration } from './providers-configuration';

export const HEADERS_PROVIDER_NAME = 'Headers';
export let HEADERS_PROVIDER: ProviderConfiguration | undefined = undefined;

export const createHeadersLoginHandler = (logger: AuthenticationProviderLogger, context: AuthContext) => async (req: any) => {
  const settings = await getSettings(context) as unknown as BasicStoreSettings;
  const headerStrategy = settings.headers_auth;
  if (!headerStrategy) {
    return undefined;
  }

  if (!await isEnterpriseEdition(context)) {
    throw ForbiddenAccess('Header authentication strategy is only available with a valid Enterprise Edition license');
  }

  logger.info('Processing login request', { headerNames: Object.keys(req.headers) }); // don't log header values for security reasons

  const resolveExpr = (expr: string) => (obj: unknown) => {
    const headers = obj as Record<string, string>;
    return headers[expr.toLowerCase()];
  };
  const mapper = createMapper(headerStrategy, resolveExpr);
  const providerLoginInfo = await mapper(req.headers);

  // since header provider is in auto mode, do a precheck on user email to avoid to produce errors logs
  if (providerLoginInfo.userMapping.email === undefined) {
    logger.warn('Email not found in headers, skipping header authentication', providerLoginInfo);
    return undefined;
  }

  const infoWithMeta = {
    ...providerLoginInfo,
    userMapping: {
      ...providerLoginInfo.userMapping,
      provider_metadata: { headers_audit: headerStrategy.headers_audit },
    },
  };

  return handleProviderLogin(logger, infoWithMeta);
};

export const registerHeadersStrategy = async (context: AuthContext) => {
  const logger = createAuthLogger(HEADERS_PROVIDER_NAME, HEADERS_PROVIDER_NAME);

  HEADERS_PROVIDER = {
    name: HEADERS_PROVIDER_NAME,
    reqLoginHandler: createHeadersLoginHandler(logger, context),
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    provider: HEADERS_STRATEGY_IDENTIFIER,
  };
};
