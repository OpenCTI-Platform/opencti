import { extractRefererPathFromReq, setCookieError } from '../../http/httpUtils';
import type { Request, Response } from 'express';
import { loginFromProvider, sessionAuthenticateUser } from '../../domain/user';
import { executionContext } from '../../utils/access';
import { getSettings } from '../../domain/settings';
import type { BasicStoreSettings } from '../../types/settings';
import { createMapper } from './mappings-utils';
import { TLSSocket } from 'node:tls';
import { createAuthLogger } from './providers-logger';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { AuthType, CERT_STRATEGY_IDENTIFIER, EnvStrategyType, type ProviderConfiguration } from './providers-configuration';

export const CERT_PROVIDER_NAME = 'Cert';
export let CERT_PROVIDER: ProviderConfiguration | undefined = undefined;

export const registerCertStrategy = async () => {
  const logger = createAuthLogger(CERT_PROVIDER_NAME, CERT_PROVIDER_NAME);

  const handleCertAuthenticationRequest = async (req: Request, res: Response) => {
    const context = executionContext('cert_strategy');
    const { cert_auth } = await getSettings(context) as unknown as BasicStoreSettings;
    const redirect = extractRefererPathFromReq(req) ?? '/';
    const isActivated = cert_auth?.enabled;
    if (!isActivated) {
      setCookieError(res, 'Cert authentication is not available');
      res.redirect(redirect);
    } else if (!await isEnterpriseEdition(context)) {
      setCookieError(res, 'Cert authentication strategy is only available with a valid Enterprise Edition license');
      res.redirect(redirect);
    } else {
      const socket = req.socket as TLSSocket;
      const cert = socket.getPeerCertificate?.();
      if (cert && socket.authorized) {
        logger.info('Valid certificate received', { cert });
        const info = await createMapper(cert_auth)(cert);

        logger.info('User info resolved', info);

        const opts = {
          providerGroups: info.groupsMapping.groups,
          autoCreateGroup: cert_auth.groups_mapping.auto_create_groups,
          preventDefaultGroups: cert_auth.groups_mapping.prevent_default_groups,
          providerOrganizations: info.organizationsMapping.organizations,
          autoCreateOrganization: cert_auth?.organizations_mapping.auto_create_organizations,
        };
        try {
          const user = await loginFromProvider(info.userMapping, opts);
          await sessionAuthenticateUser(context, req, user, 'cert');
        } catch (err: any) {
          setCookieError(res, err?.message);
        } finally {
          res.redirect(redirect);
        }
      } else {
        logger.error('Invalid certificate received', { cert });
        setCookieError(res, 'You must select a correct certificate');
        res.redirect(redirect);
      }
    }
  };

  CERT_PROVIDER = {
    name: CERT_PROVIDER_NAME,
    reqLoginHandler: handleCertAuthenticationRequest,
    type: AuthType.AUTH_SSO,
    strategy: EnvStrategyType.STRATEGY_CERT,
    provider: CERT_STRATEGY_IDENTIFIER,
  };
};
