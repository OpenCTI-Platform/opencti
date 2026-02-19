import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { getSettings } from '../../domain/settings';
import { createAuthLogger } from './providers-logger';
import { createMapper } from './mappings-utils';
import { handleProviderLogin } from './providers';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { AuthType, EnvStrategyType, HEADERS_STRATEGY_IDENTIFIER, type ProviderConfiguration } from './providers-configuration';
import { sessionAuthenticateUser } from '../../domain/user';
import type { Request, Response } from 'express';
import { extractRefererPathFromReq, setCookieError } from '../../http/httpUtils';

export const HEADERS_PROVIDER_NAME = 'Headers';
export let HEADERS_PROVIDER: ProviderConfiguration | undefined = undefined;

export const registerHeadersStrategy = async (context: AuthContext) => {
  const logger = createAuthLogger(HEADERS_PROVIDER_NAME, HEADERS_PROVIDER_NAME);

  const handleHeadersAuthenticationRequest = async (req: Request, res: Response) => {
    const settings = await getSettings(context) as unknown as BasicStoreSettings;
    const headerStrategy = settings.headers_auth;
    const redirect = extractRefererPathFromReq(req) ?? '/';
    const isActivated = headerStrategy?.enabled;
    if (!isActivated) {
      setCookieError(res, 'Headers authentication is not available');
      res.redirect(redirect);
    } else if (!await isEnterpriseEdition(context)) {
      setCookieError(res, 'Headers authentication strategy is not available');
      res.redirect(redirect);
    } else {
      logger.info('Processing login request', { headerNames: Object.keys(req.headers) }); // don't log header values for security reasons
      const resolveExpr = (expr: string) => (obj: unknown) => {
        const headers = obj as Record<string, string>;
        return headers[expr.toLowerCase()];
      };
      const mapper = createMapper(headerStrategy, resolveExpr);
      const providerLoginInfo = await mapper(req.headers);

      // since header provider is in auto mode, do a precheck on user email to avoid to produce errors logs
      if (providerLoginInfo.userMapping.email === undefined) {
        setCookieError(res, 'Headers authentication invalid configuration');
        res.redirect(redirect);
      }

      try {
        const infoWithMeta = {
          ...providerLoginInfo,
          userMapping: {
            ...providerLoginInfo.userMapping,
            provider_metadata: { headers_audit: headerStrategy.headers_audit },
          },
        };
        const user = await handleProviderLogin(logger, infoWithMeta);
        await sessionAuthenticateUser(context, req, user, 'headers');
      } catch (err: any) {
        setCookieError(res, err?.message);
      } finally {
        res.redirect(redirect);
      }
    }
  };

  HEADERS_PROVIDER = {
    name: HEADERS_PROVIDER_NAME,
    reqLoginHandler: handleHeadersAuthenticationRequest,
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    provider: HEADERS_STRATEGY_IDENTIFIER,
  };
};
