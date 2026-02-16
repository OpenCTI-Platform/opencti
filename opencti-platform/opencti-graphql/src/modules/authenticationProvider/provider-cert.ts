import { extractRefererPathFromReq, setCookieError } from '../../http/httpUtils';
import type { Request, Response } from 'express';
import { loginFromProvider, sessionAuthenticateUser } from '../../domain/user';
import { executionContext } from '../../utils/access';
import { getSettings } from '../../domain/settings';
import type { BasicStoreSettings } from '../../types/settings';
import { createMappers, resolveDotPath } from './mappings-utils';
import { TLSSocket } from 'node:tls';
import { createAuthLogger } from './providers-logger';
import { CERT_PROVIDER_NAME } from './providers';

const logger = createAuthLogger(CERT_PROVIDER_NAME, CERT_PROVIDER_NAME);
export const handleCertAuthenticationRequest = async (req: Request, res: Response) => {
  const context = executionContext('cert_strategy');
  const { cert_auth } = await getSettings(context) as unknown as BasicStoreSettings;
  const redirect = extractRefererPathFromReq(req) ?? '/';
  const isActivated = cert_auth?.enabled;
  if (!isActivated) {
    setCookieError(res, 'Cert authentication is not available');
    res.redirect(redirect);
  } else {
    const socket = req.socket as TLSSocket;
    const cert = socket.getPeerCertificate();
    if (cert && socket.authorized) {
      logger.info('Valid certificate received', { cert });
      const { resolveUserInfo, resolveGroups, resolveOrganizations } = createMappers(cert_auth);
      const resolveExpr = (expr: string) => resolveDotPath<string>(cert, expr);
      const userInfo = await resolveUserInfo(resolveExpr);
      const groups = await resolveGroups(resolveExpr);
      const organizations = await resolveOrganizations(resolveExpr);

      logger.info('User info resolved', { userInfo, groups, organizations });

      const opts = {
        providerGroups: groups,
        providerOrganizations: organizations,
        autoCreateGroup: cert_auth.groups_mapping.auto_create_groups,
        preventDefaultGroups: cert_auth.groups_mapping.prevent_default_groups,
      };
      try {
        const user = await loginFromProvider(userInfo, opts);
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
