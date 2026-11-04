import LocalStrategy from 'passport-local';
import { login } from '../user/user-domain';
import { addUserLoginCount } from '../../manager/telemetryManager';
import passport from 'passport';
import { AuthType, EnvStrategyType, LOCAL_STRATEGY_IDENTIFIER, type ProviderConfiguration } from './providers-configuration';
import { logAuthInfo } from './providers-logger';

export let LOCAL_PROVIDER: ProviderConfiguration | undefined = undefined;

export const registerLocalStrategy = async () => {
  logAuthInfo('Configuring local', EnvStrategyType.STRATEGY_LOCAL);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  // The request gives the source IP, checked against the IP whitelist before the lockout counts the attempt
  const localStrategy = new LocalStrategy({ passReqToCallback: true }, (req: { ip?: string }, username: string, password: string, done: any) => {
    return login(username, password, req.ip).then((info) => {
      logAuthInfo('User found in database', EnvStrategyType.STRATEGY_LOCAL, { username });
      addUserLoginCount();
      return done(null, info);
    }).catch((err) => {
      done(err);
    });
  });
  const providerConfig: ProviderConfiguration = {
    name: LOCAL_STRATEGY_IDENTIFIER,
    type: AuthType.AUTH_FORM,
    strategy: EnvStrategyType.STRATEGY_LOCAL,
    provider: LOCAL_STRATEGY_IDENTIFIER,
  };
  passport.use(LOCAL_STRATEGY_IDENTIFIER, localStrategy);
  LOCAL_PROVIDER = providerConfig;
};
