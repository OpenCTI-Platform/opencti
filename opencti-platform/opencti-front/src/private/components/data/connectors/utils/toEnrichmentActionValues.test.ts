import { describe, expect, it } from 'vitest';
import toEnrichmentActionValues from './toEnrichmentActionValues';

const connectors = [{ id: 'connector-1', name: 'Hygiene' }, { id: 'connector-2', name: 'Shodan' }];

describe('Function: toEnrichmentActionValues', () => {
  it('names each selected connector for the launcher, in the order they were selected', () => {
    expect(toEnrichmentActionValues(connectors, ['connector-2', 'connector-1'])).toEqual([
      { id: 'connector-2', value: 'Shodan' },
      { id: 'connector-1', value: 'Hygiene' },
    ]);
  });

  it('names all the connectors when none are selected by id', () => {
    expect(toEnrichmentActionValues(connectors)).toEqual([
      { id: 'connector-1', value: 'Hygiene' },
      { id: 'connector-2', value: 'Shodan' },
    ]);
  });

  it('leaves out the connectors not selected', () => {
    expect(toEnrichmentActionValues(connectors, ['connector-1'])).toEqual([{ id: 'connector-1', value: 'Hygiene' }]);
  });

  it('keeps the id as name for a connector missing from the list', () => {
    expect(toEnrichmentActionValues(connectors, ['connector-3'])).toEqual([{ id: 'connector-3', value: 'connector-3' }]);
  });
});
