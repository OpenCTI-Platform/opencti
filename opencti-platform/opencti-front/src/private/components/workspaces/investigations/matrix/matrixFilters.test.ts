import { describe, expect, it } from 'vitest';
import { DEFAULT_MATRIX_FILTERS, filterMatrixObjects, getMatrixFilterOptions, hasActiveMatrixFilters, type InvestigationMatrixFilters } from './matrixFilters';
import { analyseTechniqueUsage } from './ttpAnalyser';
import { NO_AUTHOR_ID, NO_MARKING_ID, type ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

interface Extra {
  objectMarking?: { id: string; definition: string }[];
  createdBy?: { id: string; name: string };
  start_time?: string;
  created_at?: string;
}

const TLP_RED = { id: 'tlp-red', definition: 'TLP:RED' };
const TLP_CLEAR = { id: 'tlp-clear', definition: 'TLP:CLEAR' };
const ACME = { id: 'acme', name: 'ACME' };
const BETA = { id: 'beta', name: 'Beta' };

const ap = (id: string) => (
  { id, entity_type: 'Attack-Pattern', name: id, parent_types: [] } as unknown as ObjectToParse
);

const entity = (id: string, entity_type: string, extra: Extra = {}) => (
  { id, entity_type, name: id, parent_types: [], ...extra } as unknown as ObjectToParse
);

const rel = (id: string, relationship_type: string, fromId: string, toId: string, extra: Extra = {}) => ({
  id,
  entity_type: relationship_type === 'object' ? 'stix-ref-relationship' : 'stix-core-relationship',
  relationship_type,
  parent_types: ['basic-relationship'],
  from: { id: fromId },
  to: { id: toId },
  ...extra,
}) as unknown as ObjectToParse;

const filters = (patch: Partial<InvestigationMatrixFilters>): InvestigationMatrixFilters => ({
  ...DEFAULT_MATRIX_FILTERS,
  ...patch,
});

const ids = (objects: ObjectToParse[]) => objects.map(({ id }) => id);

// One attack pattern scored twice: used by an intrusion set, held by a report.
const AP1 = ap('ap1');
const INTRUSION_SET = entity('is-a', 'Intrusion-Set', { objectMarking: [TLP_CLEAR], createdBy: ACME });
const REPORT = entity('report', 'Report', { objectMarking: [TLP_CLEAR], createdBy: BETA, created_at: '2024-06-01T00:00:00.000Z' });
const USES = rel('uses-1', 'uses', 'is-a', 'ap1', { objectMarking: [TLP_CLEAR], createdBy: ACME, start_time: '2024-01-10T00:00:00.000Z' });
// A contains link carries only its created_at: no marking, no author, no other date.
const CONTAINS = rel('contains-1', 'object', 'report', 'ap1', { created_at: '2024-06-01T00:00:00.000Z' });
const OBJECTS = [AP1, INTRUSION_SET, REPORT, USES, CONTAINS];

describe('filterMatrixObjects', () => {
  it('keeps every object with the default filters', () => {
    expect(filterMatrixObjects(OBJECTS, DEFAULT_MATRIX_FILTERS)).toEqual(OBJECTS);
  });

  it('drops the links of a disabled relationship type, contains included', () => {
    expect(analyseTechniqueUsage(OBJECTS).get('ap1')?.score).toBe(2);
    const result = filterMatrixObjects(OBJECTS, filters({ disabledRelationshipTypes: ['object'] }));
    expect(ids(result)).toEqual(['ap1', 'is-a', 'report', 'uses-1']);
    expect(analyseTechniqueUsage(result).get('ap1')?.score).toBe(1);
  });

  it('drops the links to a disabled linked entity type', () => {
    const result = filterMatrixObjects(OBJECTS, filters({ disabledEntityTypes: ['Intrusion-Set'] }));
    expect(ids(result)).toEqual(['ap1', 'is-a', 'report', 'contains-1']);
    expect(analyseTechniqueUsage(result).get('ap1')?.linkedEntities.map(({ id }) => id)).toEqual(['report']);
  });

  it('drops a link marked with a disabled marking, on the link or on its linked entity', () => {
    const redLink = rel('uses-red', 'uses', 'is-a', 'ap1', { objectMarking: [TLP_RED] });
    const redEntity = entity('tool-red', 'Tool', { objectMarking: [TLP_RED] });
    const toRedEntity = rel('uses-tool', 'uses', 'ap1', 'tool-red', { objectMarking: [TLP_CLEAR] });
    const objects = [AP1, INTRUSION_SET, redEntity, USES, redLink, toRedEntity];
    const result = filterMatrixObjects(objects, filters({ disabledMarkings: ['tlp-red'] }));
    expect(ids(result)).toEqual(['ap1', 'is-a', 'tool-red', 'uses-1']);
  });

  it('never filters on the markings or the author of the attack pattern', () => {
    const markedAp = entity('ap-red', 'Attack-Pattern', { objectMarking: [TLP_RED], createdBy: BETA });
    const objects = [markedAp, INTRUSION_SET, rel('uses-2', 'uses', 'is-a', 'ap-red', { objectMarking: [TLP_CLEAR], createdBy: ACME })];
    const result = filterMatrixObjects(objects, filters({ disabledMarkings: ['tlp-red'], disabledCreators: ['beta'] }));
    expect(result).toEqual(objects);
  });

  it('drops a link whose author, or whose linked entity author, is disabled', () => {
    const byBeta = rel('uses-beta', 'uses', 'is-a', 'ap1', { objectMarking: [TLP_CLEAR], createdBy: BETA });
    const objects = [AP1, INTRUSION_SET, USES, byBeta];
    expect(ids(filterMatrixObjects(objects, filters({ disabledCreators: ['beta'] })))).toEqual(['ap1', 'is-a', 'uses-1']);
    // ACME wrote the intrusion set: both links to it go.
    expect(ids(filterMatrixObjects(objects, filters({ disabledCreators: ['acme'] })))).toEqual(['ap1', 'is-a']);
  });

  it('gives a contains link the markings and author of its container', () => {
    expect(ids(filterMatrixObjects(OBJECTS, filters({ disabledCreators: ['beta'] }))))
      .toEqual(['ap1', 'is-a', 'report', 'uses-1']);
    const redReport = entity('report', 'Report', { objectMarking: [TLP_RED], createdBy: BETA });
    const objects = [AP1, INTRUSION_SET, redReport, USES, CONTAINS];
    expect(ids(filterMatrixObjects(objects, filters({ disabledMarkings: ['tlp-red'] }))))
      .toEqual(['ap1', 'is-a', 'report', 'uses-1']);
  });

  it('puts a link without marking or author under None', () => {
    // A contains link from a container with no marking and no author.
    const bareReport = entity('report', 'Report');
    const objects = [AP1, INTRUSION_SET, bareReport, USES, CONTAINS];
    expect(ids(filterMatrixObjects(objects, filters({ disabledMarkings: [NO_MARKING_ID] }))))
      .toEqual(['ap1', 'is-a', 'report', 'uses-1']);
    expect(ids(filterMatrixObjects(objects, filters({ disabledCreators: [NO_AUTHOR_ID] }))))
      .toEqual(['ap1', 'is-a', 'report', 'uses-1']);
    // The intrusion set link and its entity are marked and authored: "None" leaves them alone.
    expect(analyseTechniqueUsage(filterMatrixObjects(objects, filters({ disabledMarkings: [NO_MARKING_ID] }))).get('ap1')?.score).toBe(1);
  });

  it('drops the links dated outside the time range, a contains link dated by its created_at', () => {
    const beforeJune = filters({ timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'] });
    expect(ids(filterMatrixObjects(OBJECTS, beforeJune))).toEqual(['ap1', 'is-a', 'report', 'uses-1']);
    const june = filters({ timeRange: ['2024-05-01T00:00:00.000Z', '2024-07-01T00:00:00.000Z'] });
    expect(ids(filterMatrixObjects(OBJECTS, june))).toEqual(['ap1', 'is-a', 'report', 'contains-1']);
  });

  it('keeps an undated link under a time range', () => {
    const undated = rel('uses-undated', 'uses', 'is-a', 'ap1', { objectMarking: [TLP_CLEAR], createdBy: ACME });
    const objects = [AP1, INTRUSION_SET, undated];
    const result = filterMatrixObjects(objects, filters({ timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'] }));
    expect(result).toEqual(objects);
    expect(analyseTechniqueUsage(result).get('ap1')?.score).toBe(1);
  });

  it('never drops an entity, so the matrix still places every attack pattern', () => {
    const everything = filters({
      disabledEntityTypes: ['Intrusion-Set', 'Report'],
      disabledRelationshipTypes: ['uses', 'indicates', 'object'],
      disabledMarkings: ['tlp-clear', NO_MARKING_ID],
      disabledCreators: ['acme', 'beta', NO_AUTHOR_ID],
      timeRange: ['2030-01-01T00:00:00.000Z', '2030-02-01T00:00:00.000Z'],
    });
    const result = filterMatrixObjects(OBJECTS, everything);
    expect(ids(result)).toEqual(['ap1', 'is-a', 'report']);
    expect(analyseTechniqueUsage(result).size).toBe(0);
  });

  it('drops a uses between two attack patterns as soon as one of its two links is dropped', () => {
    const redAp = entity('ap-red', 'Attack-Pattern', { objectMarking: [TLP_RED] });
    const objects = [AP1, redAp, rel('ap-uses-ap', 'uses', 'ap1', 'ap-red', { objectMarking: [TLP_CLEAR] })];
    expect(analyseTechniqueUsage(objects).size).toBe(2);
    const result = filterMatrixObjects(objects, filters({ disabledMarkings: ['tlp-red'] }));
    expect(ids(result)).toEqual(['ap1', 'ap-red']);
  });

  it('keeps the relationships that score nothing', () => {
    const tool = entity('tool', 'Tool');
    const other = rel('related', 'related-to', 'is-a', 'tool', { objectMarking: [TLP_RED] });
    const objects = [AP1, INTRUSION_SET, tool, USES, other];
    expect(ids(filterMatrixObjects(objects, filters({ disabledMarkings: ['tlp-red'], disabledRelationshipTypes: ['uses'] }))))
      .toEqual(['ap1', 'is-a', 'tool', 'related']);
  });
});

describe('hasActiveMatrixFilters', () => {
  it('is false for the defaults and true as soon as one filter is set', () => {
    expect(hasActiveMatrixFilters(DEFAULT_MATRIX_FILTERS)).toBe(false);
    expect(hasActiveMatrixFilters(filters({ disabledEntityTypes: ['Report'] }))).toBe(true);
    expect(hasActiveMatrixFilters(filters({ disabledRelationshipTypes: ['uses'] }))).toBe(true);
    expect(hasActiveMatrixFilters(filters({ disabledMarkings: ['tlp-red'] }))).toBe(true);
    expect(hasActiveMatrixFilters(filters({ disabledCreators: ['acme'] }))).toBe(true);
    expect(hasActiveMatrixFilters(filters({ timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'] }))).toBe(true);
  });
});

describe('getMatrixFilterOptions', () => {
  it('lists only the types, markings and authors found on scoring links', () => {
    const indicator = entity('ind', 'Indicator', { objectMarking: [TLP_RED], createdBy: ACME });
    // Not a scoring link: its marking, author and entity type stay out of the options.
    const malware = entity('malware', 'Malware', { objectMarking: [{ id: 'pap', definition: 'PAP:RED' }], createdBy: { id: 'gamma', name: 'Gamma' } });
    const objects = [
      AP1,
      INTRUSION_SET,
      REPORT,
      indicator,
      malware,
      CONTAINS,
      USES,
      rel('ind-1', 'indicates', 'ind', 'ap1', { objectMarking: [TLP_RED], createdBy: ACME, start_time: '2024-03-01T00:00:00.000Z' }),
      rel('related', 'related-to', 'malware', 'ap1', { objectMarking: [{ id: 'pap', definition: 'PAP:RED' }] }),
    ];
    const options = getMatrixFilterOptions(objects, 'None');
    expect(options.entityTypes).toEqual(['Indicator', 'Intrusion-Set', 'Report']);
    expect(options.relationshipTypes).toEqual(['uses', 'indicates', 'object']);
    expect(options.markings).toEqual([TLP_CLEAR, TLP_RED]);
    expect(options.authors).toEqual([ACME, BETA]);
    expect(options.datedLinks.map(({ defaultDate }) => defaultDate.toISOString())).toEqual([
      '2024-06-01T00:00:00.000Z',
      '2024-01-10T00:00:00.000Z',
      '2024-03-01T00:00:00.000Z',
    ]);
    expect(options.datedLinks[0].parent_types).toEqual(['basic-relationship']);
  });

  it('keeps the first occurrence of each marking, author and relationship, in order', () => {
    const ap2 = ap('ap2');
    // The same marking and author ids come back with other labels on later links: the first wins.
    const objects = [
      AP1,
      ap2,
      INTRUSION_SET,
      rel('first', 'uses', 'is-a', 'ap1', { objectMarking: [TLP_CLEAR], createdBy: ACME, start_time: '2024-03-01T00:00:00.000Z' }),
      // Scores both ends, so it gives two links but one dated entry.
      rel('ap-uses-ap', 'uses', 'ap1', 'ap2', { objectMarking: [{ id: 'tlp-clear', definition: 'Renamed' }], createdBy: { id: 'acme', name: 'Renamed' }, start_time: '2024-01-01T00:00:00.000Z' }),
      rel('last', 'uses', 'is-a', 'ap2', { objectMarking: [TLP_CLEAR], createdBy: ACME, start_time: '2024-02-01T00:00:00.000Z' }),
    ];
    const options = getMatrixFilterOptions(objects, 'None');
    expect(options.markings).toEqual([{ id: NO_MARKING_ID, definition: 'None' }, TLP_CLEAR]);
    expect(options.authors).toEqual([ACME, { id: NO_AUTHOR_ID, name: 'None' }]);
    expect(options.datedLinks.map(({ defaultDate }) => defaultDate.toISOString())).toEqual([
      '2024-03-01T00:00:00.000Z',
      '2024-01-01T00:00:00.000Z',
      '2024-02-01T00:00:00.000Z',
    ]);
  });

  it('labels the None entries with the given label', () => {
    const objects = [AP1, entity('report', 'Report'), CONTAINS];
    const options = getMatrixFilterOptions(objects, 'Aucun');
    expect(options.relationshipTypes).toEqual(['object']);
    expect(options.markings).toEqual([{ id: NO_MARKING_ID, definition: 'Aucun' }]);
    expect(options.authors).toEqual([{ id: NO_AUTHOR_ID, name: 'Aucun' }]);
  });

  it('lists nothing without scoring links', () => {
    expect(getMatrixFilterOptions([AP1, INTRUSION_SET], 'None')).toEqual({
      entityTypes: [],
      relationshipTypes: [],
      markings: [],
      authors: [],
      datedLinks: [],
    });
  });
});
