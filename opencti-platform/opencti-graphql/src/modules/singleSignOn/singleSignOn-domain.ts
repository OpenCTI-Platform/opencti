import type { AuthContext, AuthUser } from '../../types/user';
import { type SingleSignMigrationInput } from '../../generated/graphql';
import { UnsupportedError } from '../../config/errors';
import { logApp } from '../../config/conf';
import nconf from 'nconf';
import { parseSingleSignOnRunConfiguration } from './singleSignOn-migration';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';

export const checkSSOAllowed = async (context: AuthContext) => {
  if (!await isEnterpriseEdition(context)) throw UnsupportedError('Enterprise licence is required');
};

export const runSingleSignOnRunMigration = async (context: AuthContext, user: AuthUser, input: SingleSignMigrationInput) => {
  await checkSSOAllowed(context);
  logApp.info(`[SSO MIGRATION] Migration requested with dry_run = ${input.dry_run}`);
  const ssoConfigurationEnv = nconf.get('providers');
  return parseSingleSignOnRunConfiguration(context, user, ssoConfigurationEnv, input.dry_run);
};
