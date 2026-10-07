import type { GraphQLError } from 'graphql';
import { InfraError } from '../config/errors';
import { APP_MODULE, type Dependency, tagErrorModule } from '../config/error-origin';

// The one place where the failures of a dependency are classified (RFC 0006).
// Each shared client defines its dependency once, with the predicate telling an unavailable
// or failing service from a request it rejected, and routes every call through it.
// Rules for a shared client:
// - throw or log, never both: a failure with a caller is thrown, and logged once by the error boundary;
// - never swallow: whether a failure is acceptable is the caller's decision (see `bestEffort`);
// - retry before classifying: a failure classified here is final for the caller.
export interface DependencyClientDefinition {
  dependency: Dependency;
  // Called on a failure the client's own retries could not absorb.
  isUnavailable: (err: unknown) => boolean;
  unavailableMessage: string;
  // The error thrown when the service is unavailable, `InfraError` by default. A client whose callers already
  // know another code keeps it: the `dependency` named in the data is what makes the error an infra error.
  errorFactory?: (reason: string, data: Record<string, unknown>) => GraphQLError;
}

export interface ClassifyOptions {
  operation?: string;
  reason?: string;
  [key: string]: unknown;
}

export const defineDependencyClient = ({
  dependency,
  isUnavailable,
  unavailableMessage,
  errorFactory = (reason, data) => InfraError(dependency, reason, data),
}: DependencyClientDefinition) => {
  // - The service is unavailable or failing: a typed infra error, `origin: infra`, original error as `cause`.
  // - A bug in the client or in the library it wraps: tagged `core`, `origin: code`.
  // - The service rejected our request: untouched, the calling module owns it.
  const classify = (err: unknown, { reason, ...data }: ClassifyOptions = {}) => {
    if (isUnavailable(err)) {
      return errorFactory(reason ?? unavailableMessage, { ...data, dependency, cause: err });
    }
    if (err instanceof TypeError) {
      return tagErrorModule(err, APP_MODULE.CORE);
    }
    return err;
  };

  const call = async <T>(operation: string, fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (err) {
      throw classify(err, { operation });
    }
  };

  return { dependency, classify, call };
};

export type DependencyClient = ReturnType<typeof defineDependencyClient>;
