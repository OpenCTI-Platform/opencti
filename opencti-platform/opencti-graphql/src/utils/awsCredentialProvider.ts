// A credential provider of the AWS SDK (defaultProvider) memoizes the credentials it resolves:
// it reuses them until shortly before they expire and shares one refresh between concurrent callers.
// That memoization only works when the same provider instance is called again, so the provider
// must be created once and reused, never rebuilt on every call (one STS call per request otherwise).
export const createSharedCredentialProvider = <T>(factory: () => () => Promise<T>): (() => Promise<T>) => {
  let provider: (() => Promise<T>) | undefined;
  return () => {
    if (!provider) {
      provider = factory();
    }
    return provider();
  };
};
