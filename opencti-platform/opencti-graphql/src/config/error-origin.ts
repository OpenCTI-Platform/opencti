import { AUTH_ERRORS, FUNCTIONAL_ERRORS, INFRA_ERROR } from './errors';

// Module-scoped error classification (RFC 0006).
// Every error record says which module raised it (`module`) and whether the code,
// a dependency or the input is at fault (`origin`).

// region modules
// Closed enum: alert routing and metric labels stay bounded.
// `core` is the code shared by every module (middleware, shared clients).
export const APP_MODULE = {
  CORE: 'core',
  CATALOG: 'catalog',
  CONNECTOR: 'connector',
} as const;
export type AppModule = typeof APP_MODULE[keyof typeof APP_MODULE];
// endregion

// region dependencies
// The services outside the process. `remote_http`: a remote endpoint reached over HTTP.
export const DEPENDENCIES = ['elasticsearch', 'rabbitmq', 'redis', 's3', 'remote_http'] as const;
export type Dependency = typeof DEPENDENCIES[number];
// endregion

// region error context
// Identifiers a layer knows and the error boundary doesn't (which catalog, which item of a batch).
// Attached to the error itself: its class, message and origin don't change, and unlike the `data` of our
// error factories (sent to GraphQL clients in `extensions.data`), it never leaves the platform.
// Identifiers and counts only: never intelligence content, never in the message, never a metric label.
const ERROR_CONTEXT = Symbol('errorContext');
export type ErrorContext = Record<string, string | number | boolean | null | undefined>;
type ContextualError = object & { [ERROR_CONTEXT]?: ErrorContext };

// A key already set, closer to the failure, wins.
export const withErrorContext = <T>(e: T, context: ErrorContext): T => {
  if (e !== null && typeof e === 'object') {
    const contextual = e as ContextualError;
    contextual[ERROR_CONTEXT] = { ...context, ...contextual[ERROR_CONTEXT] };
  }
  return e;
};

// Add context to whatever the call throws or rejects with.
export const runWithErrorContext = async <T>(context: ErrorContext, call: () => Promise<T>): Promise<T> => {
  try {
    return await call();
  } catch (e) {
    throw withErrorContext(e, context);
  }
};
// endregion

// region module tag
const MODULE_TAG = Symbol('moduleTag');
type TaggableError = object & { [MODULE_TAG]?: AppModule };

// Tag an error with the module it leaves, and the public API function it left through.
// A tag already set is kept: the innermost module wins.
export const tagErrorModule = <T>(e: T, module: AppModule, api?: string): T => {
  if (e !== null && typeof e === 'object' && !(MODULE_TAG in e)) {
    (e as TaggableError)[MODULE_TAG] = module;
    if (api) {
      withErrorContext(e, { api });
    }
  }
  return e;
};

// Wrap a function of a module public API, so that the errors it throws or rejects with are tagged.
export const withModuleTag = <F extends (...args: any[]) => any>(module: AppModule, fn: F, api?: string): F => {
  return ((...args: Parameters<F>) => {
    try {
      const result = fn(...args);
      if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
        return Promise.resolve(result).catch((e: unknown) => {
          throw tagErrorModule(e, module, api);
        });
      }
      return result;
    } catch (e) {
      throw tagErrorModule(e, module, api);
    }
  }) as F;
};

// Wrap every function of a module public API. Errors record the function they left through,
// as `api: '<module>.<function>'` in their context: the call another module made.
export const withModuleApi = <T extends Record<string, unknown>>(module: AppModule, api: T): T => {
  const wrapped: Record<string, unknown> = {};
  Object.entries(api).forEach(([name, value]) => {
    wrapped[name] = typeof value === 'function' ? withModuleTag(module, value as (...args: any[]) => any, `${module}.${name}`) : value;
  });
  return wrapped as T;
};
// endregion

// region error chain
const MAX_CHAIN_DEPTH = 10;

// The error and its causes, outermost first. Follows Apollo's `originalError`,
// the native `cause`, and the `cause` our error factories put in `extensions.data`.
export const errorChain = (e: unknown): object[] => {
  const chain: object[] = [];
  let current: any = e;
  while (current !== null && typeof current === 'object' && !chain.includes(current) && chain.length < MAX_CHAIN_DEPTH) {
    chain.push(current);
    current = current.originalError ?? current.cause ?? current.extensions?.data?.cause;
  }
  return chain;
};

const errorCode = (e: any): string | undefined => e?.extensions?.code ?? e?.code;

// The context of the whole chain. On a key set at several levels, the innermost wins.
export const resolveErrorContext = (e: unknown): ErrorContext | undefined => {
  let merged: ErrorContext | undefined;
  errorChain(e).forEach((item) => {
    const context = (item as ContextualError)[ERROR_CONTEXT];
    if (context) {
      merged = { ...merged, ...context };
    }
  });
  return merged;
};

// The innermost module tag in the chain: where the error was raised.
export const resolveErrorModule = (e: unknown): AppModule | undefined => {
  let module: AppModule | undefined;
  errorChain(e).forEach((item) => {
    const tag = (item as TaggableError)[MODULE_TAG];
    if (tag) {
      module = tag;
    }
  });
  return module;
};
// endregion

// region origin
export type ErrorOrigin = 'code' | 'infra' | 'input';

// The codes the GraphQL boundary already logged below ERROR before this classification.
// Races (ALREADY_DELETED_ERROR) and locks stay here until RFC 0006 open questions 6 and 7 are settled.
const INPUT_ERROR_CODES: string[] = [...AUTH_ERRORS, ...FUNCTIONAL_ERRORS];

const isInfraError = (e: unknown) => errorCode(e) === INFRA_ERROR;

// - A typed infra error anywhere in the chain: a dependency failed, whoever wrapped it.
// - Else a typed input error at the top: the code rejected the input on purpose.
//   A module that rethrows another module's rejection as its own bug wraps it in a non-input error.
// - Anything else is a bug until proven otherwise.
export const classifyErrorOrigin = (e: unknown): ErrorOrigin => {
  const chain = errorChain(e);
  if (chain.some(isInfraError)) {
    return 'infra';
  }
  const code = errorCode(chain[0]);
  if (code && INPUT_ERROR_CODES.includes(code)) {
    return 'input';
  }
  return 'code';
};

export const resolveErrorDependency = (e: unknown): Dependency | undefined => {
  const infraError: any = errorChain(e).find(isInfraError);
  return infraError?.extensions?.data?.dependency;
};

// Node.js network failures: the remote service could not be reached at all.
const NETWORK_FAILURE_CODES = ['ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE'];

export const isNetworkFailure = (e: unknown): boolean => {
  return errorChain(e).some((item) => NETWORK_FAILURE_CODES.includes(errorCode(item) ?? ''));
};
// endregion

// region scope and level
export interface ErrorScope {
  module?: AppModule;
  entry_module?: AppModule;
  origin: ErrorOrigin;
  dependency?: Dependency;
}

// `entryModule` is the module whose resolver, manager or consumer was running.
// An error without a tag is attributed to it: no tag, no guess.
export const buildErrorScope = (e: unknown, entryModule?: AppModule): ErrorScope => {
  const origin = classifyErrorOrigin(e);
  const scope: ErrorScope = { origin };
  const module = resolveErrorModule(e) ?? entryModule;
  if (module) {
    scope.module = module;
  }
  if (entryModule) {
    scope.entry_module = entryModule;
  }
  if (origin === 'infra') {
    const dependency = resolveErrorDependency(e);
    if (dependency) {
      scope.dependency = dependency;
    }
  }
  return scope;
};

// RFC 0006 §4.6, option A: ERROR means a code fault.
// As in OpenTelemetry's exception conventions, a dependency failure after retries is WARN,
// even for the platform's own Elasticsearch, Redis, RabbitMQ or S3. Rejected input is never ERROR.
export const levelForOrigin = (origin: ErrorOrigin): 'error' | 'warn' => {
  return origin === 'code' ? 'error' : 'warn';
};
// endregion
