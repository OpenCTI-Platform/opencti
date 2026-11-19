import { describe, expect, it } from 'vitest';
import { resolveSortBy } from './ContainerStixDomainObjects';

describe('resolveSortBy', () => {
  it('falls back to the default sort when none is stored', () => {
    // Without a fallback, page 1 is sent without orderBy (1-value cursor) while the refetch
    // uses the fragment default (2 sort keys): Elasticsearch rejects the search_after.
    expect(resolveSortBy(undefined)).toEqual('name');
  });

  it('keeps the stored sort', () => {
    expect(resolveSortBy('created_at')).toEqual('created_at');
  });

  it('keeps the relevance sort set by a search', () => {
    expect(resolveSortBy('_score')).toEqual('_score');
  });
});
