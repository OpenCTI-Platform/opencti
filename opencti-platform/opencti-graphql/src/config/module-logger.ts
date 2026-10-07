import { logApp } from './conf';
import { type AppModule, buildErrorScope, type ErrorScope, levelForOrigin, resolveErrorContext } from './error-origin';

type LogMeta = Record<string, unknown>;

// A logger for the code of one module: every record carries `module`.
export const createModuleLogger = (module: AppModule) => ({
  debug: (message: string, meta: LogMeta = {}) => logApp.debug(message, { ...meta, module }),
  info: (message: string, meta: LogMeta = {}) => logApp.info(message, { ...meta, module }),
  warn: (message: string, meta: LogMeta = {}) => logApp.warn(message, { ...meta, module }),
  error: (message: string, meta: LogMeta = {}) => logApp.error(message, { ...meta, module }),
});

export type ModuleLogger = ReturnType<typeof createModuleLogger>;

// Log an error once, where it is caught for good: GraphQL and HTTP error handlers,
// manager run loops, stream and queue consumers.
// `origin`, `module` and the level are derived from the error, not chosen by the caller:
// ERROR for a code fault, WARN for a dependency failure or rejected input (RFC 0006 §4.6, option A).
// The context the error picked up on its way (`withErrorContext`) goes under `error_context`.
export const logBoundaryError = (
  message: string,
  error: unknown,
  { entryModule, ...meta }: LogMeta & { entryModule?: AppModule } = {},
): ErrorScope => {
  const scope = buildErrorScope(error, entryModule);
  const errorContext = resolveErrorContext(error);
  logApp[levelForOrigin(scope.origin)](message, {
    ...meta,
    ...scope,
    ...(errorContext ? { error_context: errorContext } : {}),
    cause: error,
  });
  return scope;
};

// An operation whose failure the caller accepts: the failure is logged once with its origin
// (a bug stays ERROR, an unavailable dependency is WARN), then the caller continues.
// The explicit counterpart of the shared client rule "never swallow": the decision is visible at the call site.
export const bestEffort = async <T>(
  operation: string,
  call: () => Promise<T>,
  { entryModule, ...meta }: LogMeta & { entryModule?: AppModule } = {},
): Promise<T | undefined> => {
  try {
    return await call();
  } catch (error) {
    logBoundaryError('[BEST-EFFORT] Operation failed, continuing', error, { ...meta, operation, entryModule });
    return undefined;
  }
};
