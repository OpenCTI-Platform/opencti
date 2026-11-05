import { describe, expect, it } from 'vitest';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import {
  countExpandOptions,
  ExpandElement,
  isNothingToExpand,
  selectExpandIds,
  toEnrichmentSelection,
  toEnrichmentTaskActions,
  toExpandElements,
} from './investigation-enrichment.utils';

const malware: ExpandElement = { id: 'malware-1', entity_type: 'Malware' };
const indicator: ExpandElement = { id: 'indicator-1', entity_type: 'Indicator' };
const otherIndicator: ExpandElement = { id: 'indicator-2', entity_type: 'Indicator' };
const indicates: ExpandElement = { id: 'rel-1', entity_type: 'indicates', fromId: 'indicator-1', toId: 'malware-1' };
const uses: ExpandElement = { id: 'rel-2', entity_type: 'uses', fromId: 'source-id', toId: 'tool-1' };

/**
 * A work reduced to its touched elements, the only field toExpandElements reads.
 */
const workTouching = (elements: ExpandElement[]) => ({ touchedElements: elements }) as unknown as InvestigationEnrichmentWork;

describe('Function: toExpandElements', () => {
  it('keeps once an element touched by several works', () => {
    expect(toExpandElements([workTouching([malware, indicates]), workTouching([malware, indicator])]))
      .toEqual([malware, indicates, indicator]);
  });

  it('leaves out an element without id or type', () => {
    expect(toExpandElements([workTouching([malware, { id: '', entity_type: 'Tool' }])])).toEqual([malware]);
  });
});

describe('Function: countExpandOptions', () => {
  it('counts the entities by type and the relationships by type', () => {
    const { targets, relationships } = countExpandOptions(
      [malware, indicator, otherIndicator, indicates, uses],
      new Set(),
    );
    expect([...targets.entries()]).toEqual([['Malware', 1], ['Indicator', 2]]);
    expect([...relationships.entries()]).toEqual([['indicates', 1], ['uses', 1]]);
  });

  it('leaves out what is already on the graph', () => {
    const { targets, relationships } = countExpandOptions(
      [malware, indicator, indicates],
      new Set(['malware-1', 'rel-1']),
    );
    expect([...targets.entries()]).toEqual([['Indicator', 1]]);
    expect([...relationships.entries()]).toEqual([]);
  });
});

describe('Function: isNothingToExpand', () => {
  it('is true when everything touched is already on the graph', () => {
    expect(isNothingToExpand([malware, indicates], new Set(['malware-1', 'rel-1']))).toBe(true);
  });

  it('is true when nothing was touched', () => {
    expect(isNothingToExpand([], new Set())).toBe(true);
  });

  it('is false when something touched is not on the graph', () => {
    expect(isNothingToExpand([malware, indicator], new Set(['malware-1']))).toBe(false);
  });
});

describe('Function: selectExpandIds', () => {
  const elements = [malware, indicator, otherIndicator, indicates, uses];

  it('adds only the entities of a ticked type, without their relationships', () => {
    expect(selectExpandIds(elements, new Set(), ['Indicator'], [])).toEqual(['indicator-1', 'indicator-2']);
  });

  it('adds a relationship of a ticked type with both of its ends', () => {
    expect(selectExpandIds(elements, new Set(), [], ['indicates'])).toEqual(['rel-1', 'indicator-1', 'malware-1']);
  });

  it('adds the ends of a relationship even when they were not touched', () => {
    expect(selectExpandIds(elements, new Set(['source-id']), [], ['uses'])).toEqual(['rel-2', 'tool-1']);
  });

  it('adds nothing already on the graph', () => {
    expect(selectExpandIds(elements, new Set(['indicator-1', 'rel-2']), ['Indicator'], ['uses'])).toEqual(['indicator-2']);
  });

  it('adds each element once', () => {
    expect(selectExpandIds(elements, new Set(), ['Indicator', 'Malware'], ['indicates'])).toEqual(['malware-1', 'indicator-1', 'indicator-2', 'rel-1']);
  });
});

describe('Function: toEnrichmentSelection', () => {
  const ip = { id: 'ip-1', label: '198.51.100.7', entity_type: 'IPv4-Addr' };
  const otherIp = { id: 'ip-2', label: '203.0.113.24', entity_type: 'IPv4-Addr' };
  const domain = { id: 'domain-1', label: 'example.com', entity_type: 'Domain-Name' };

  it('gives the type of a selection of one type, with its elements named after their label', () => {
    const { selectionMap, selectionSize, enrichmentType } = toEnrichmentSelection([ip, otherIp]);
    expect(enrichmentType).toBe('IPv4-Addr');
    expect(selectionSize).toBe(2);
    expect(selectionMap['ip-1']).toEqual({ ...ip, name: '198.51.100.7' });
  });

  it('gives no type to a selection mixing types, or to an empty one', () => {
    expect(toEnrichmentSelection([ip, domain]).enrichmentType).toBeUndefined();
    expect(toEnrichmentSelection([]).enrichmentType).toBeUndefined();
  });
});

describe('Function: toEnrichmentTaskActions', () => {
  it('enriches with the connectors and tags the works with the investigation', () => {
    expect(toEnrichmentTaskActions(['connector-1'], 'investigation-1')).toEqual([{
      type: 'ENRICHMENT',
      context: { values: ['connector-1'], options: { investigationId: 'investigation-1' } },
    }]);
  });
});
