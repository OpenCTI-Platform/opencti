import { Kind, type OperationDefinitionNode } from 'graphql';
import type { AppModule } from '../config/error-origin';

// Which module registered each root field (`Query.catalogs`, `Mutation.connectorAdd`...).
// The GraphQL error boundary reads it to know the entry module of a failed call (RFC 0006).
const ROOT_TYPES = { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' } as const;
const rootFieldModules = new Map<string, AppModule>();

export const registerRootFieldModules = (module: AppModule, resolver: Record<string, unknown>) => {
  Object.values(ROOT_TYPES).forEach((rootType) => {
    const fields = resolver[rootType];
    if (fields && typeof fields === 'object') {
      Object.keys(fields).forEach((field) => rootFieldModules.set(`${rootType}.${field}`, module));
    }
  });
};

// An error path starts with the response key of the root field, which is the alias if any.
const resolveRootFieldName = (operation: OperationDefinitionNode, responseKey: string) => {
  const selection = operation.selectionSet.selections.find((candidate) => {
    return candidate.kind === Kind.FIELD && (candidate.alias?.value ?? candidate.name.value) === responseKey;
  });
  return selection?.kind === Kind.FIELD ? selection.name.value : responseKey;
};

export const resolveEntryModule = (operation: OperationDefinitionNode | undefined | null, path: ReadonlyArray<string | number> | undefined) => {
  const responseKey = path?.[0];
  if (!operation || typeof responseKey !== 'string') {
    return undefined;
  }
  const rootType = ROOT_TYPES[operation.operation];
  return rootFieldModules.get(`${rootType}.${resolveRootFieldName(operation, responseKey)}`);
};
