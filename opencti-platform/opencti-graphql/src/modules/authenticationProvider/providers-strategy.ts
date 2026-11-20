import passport from 'passport';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import type { AuthenticationProviderLogger } from './providers-logger';

export type ProviderStrategy = passport.Strategy & { logger?: AuthenticationProviderLogger };

// _strategy is an undocumented passport API, not part of its type definitions
type PassportWithStrategies = { _strategy: (name: string) => ProviderStrategy | undefined };

// Strategy registered under this provider identifier on this node, undefined when the provider is unknown or disabled
export const findProviderStrategy = (provider: string): ProviderStrategy | undefined => {
  return (passport as unknown as PassportWithStrategies)._strategy(provider);
};

// SAML relays the application state through RelayState, the other SSO strategies keep it in the session
export const isSamlStrategy = (strategy: unknown): strategy is SamlStrategy => strategy instanceof SamlStrategy;
