import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ApolloArmor } from '@escape.tech/graphql-armor';
import { buildSchema, parse, validate } from 'graphql';
import { describe, expect, it } from 'vitest';
import conf from '../../../src/config/conf';

// The panel query is read from the monorepo checkout: a cost over the limit rejects it on platforms with GraphQL armor
const GRAPHQL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const TOOL_FILE = path.resolve(
  GRAPHQL_ROOT,
  '../opencti-front/src/private/components/workspaces/investigations/investigations_enrichment/InvestigationEnrichmentTool.tsx',
);

const readPanelQuery = () => {
  const match = readFileSync(TOOL_FILE, 'utf8').match(/const investigationQuery = graphql`([\s\S]*?)`;/);
  if (!match) {
    throw new Error(`investigationQuery not found in ${TOOL_FILE}`);
  }
  return match[1];
};

/**
 * The errors of the platform's cost limit on a query, the other armor protections left out.
 */
const costErrors = (query: string) => {
  const armor = new ApolloArmor({
    costLimit: { maxCost: conf.get('app:graphql:armor_protection:cost_limit') },
    blockFieldSuggestion: { enabled: false },
    maxDepth: { enabled: false },
    maxDirectives: { enabled: false },
    maxTokens: { enabled: false },
    maxAliases: { enabled: false },
  });
  const schema = buildSchema('type Query { workspace(id: String!): String }');
  try {
    return validate(schema, parse(query), armor.protect().validationRules).map((error) => error.message);
  } catch (error) {
    return [(error as Error).message];
  }
};

describe('Investigation enrichment panel query cost', () => {
  it('should stay under the GraphQL cost limit', () => {
    expect(costErrors(readPanelQuery())).toEqual([]);
  });

  it('should exceed the cost limit with a literal page size', () => {
    const query = readPanelQuery();
    const literal = query.replace('enrichmentWorks(first: $first', 'enrichmentWorks(first: 5000');
    expect(literal).not.toEqual(query);
    expect(costErrors(literal).join(' ')).toContain('Query Cost limit');
  });
});
