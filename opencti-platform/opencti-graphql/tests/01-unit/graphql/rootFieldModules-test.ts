import { type OperationDefinitionNode, parse } from 'graphql';
import { describe, expect, it } from 'vitest';
import { registerRootFieldModules, resolveEntryModule } from '../../../src/graphql/rootFieldModules';

const operationOf = (query: string) => parse(query).definitions[0] as OperationDefinitionNode;

registerRootFieldModules('catalog', {
  Query: { catalogs: () => [], contract: () => null },
  Catalog: { contracts: () => [] },
});

describe('GraphQL entry module', () => {
  it('should resolve the module of the failed root field', () => {
    const operation = operationOf('query { catalogs { id } }');
    expect(resolveEntryModule(operation, ['catalogs', 0, 'id'])).toBe('catalog');
  });

  it('should resolve an aliased root field', () => {
    const operation = operationOf('query { myContract: contract(slug: "x") { id } }');
    expect(resolveEntryModule(operation, ['myContract', 'id'])).toBe('catalog');
  });

  it('should not register the fields of non-root types', () => {
    const operation = operationOf('query { contracts { id } }');
    expect(resolveEntryModule(operation, ['contracts'])).toBeUndefined();
  });

  it('should not match a root field of another operation type', () => {
    const operation = operationOf('mutation { catalogs { id } }');
    expect(resolveEntryModule(operation, ['catalogs'])).toBeUndefined();
  });

  it('should leave an error without path or operation unattributed', () => {
    expect(resolveEntryModule(operationOf('query { catalogs { id } }'), undefined)).toBeUndefined();
    expect(resolveEntryModule(undefined, ['catalogs'])).toBeUndefined();
  });
});
