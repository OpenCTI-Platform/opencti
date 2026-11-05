/**
 * Unit tests of the public time series breakdowns: every breakdown setting is read from the stored widget, the visitor
 * only gives the period. Only the breakdowns of entities and relationships widgets are public: audits widgets can
 * carry a breakdown as well, but the logs have no public API.
 */
import { describe, expect, it } from 'vitest';
import { buildPublicBreakdownArgs, getBreakdownEntityTypes } from '../../../../src/modules/publicDashboard/publicDashboard-breakdown';

const startDate = '2026-01-01T00:00:00.000Z';
const endDate = '2026-02-01T00:00:00.000Z';

const targets = { mode: 'and', filters: [{ key: ['relationship_type'], values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const malwares = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const sectors = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const breakdownParameters = { interval: 'week', breakdownBy: 'toTypes', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true };
// The relationships the relationships widgets display, as the front restricts them (RELATIONSHIP_WIDGETS_TYPES)
const relationshipWidgetsTypes = ['stix-core-relationship', 'stix-sighting-relationship', 'object', 'object-label'];
const widgetRelationships = (storedFilters?: unknown) => ({
  mode: 'and',
  filters: [{ key: ['entity_type'], values: relationshipWidgetsTypes, operator: 'eq', mode: 'or' }],
  filterGroups: storedFilters ? [storedFilters] : [],
});

const storedWidget = (perspective: string | null, dataSelection: unknown[], parameters: unknown, type = 'line') => {
  return { type, perspective, dataSelection, parameters } as any;
};
const request = (overrides: Record<string, unknown> = {}) => ({ widgetId: 'widget-1', startDate, endDate, ...overrides } as any);

describe('buildPublicBreakdownArgs of relationships', () => {
  const relationshipsArgs = (widget: unknown, overrides: Record<string, unknown> = {}) => {
    return buildPublicBreakdownArgs(request(overrides), widget as any, 'relationships');
  };

  it('should break the stored dataset down with the stored settings', () => {
    const widget = storedWidget('relationships', [{ date_attribute: 'start_time', filters: targets, dynamicFrom: malwares, dynamicTo: sectors, isTo: false }], breakdownParameters);
    const args = relationshipsArgs(widget);

    expect(args).toEqual({
      field: 'toTypes',
      dateAttribute: 'start_time',
      startDate,
      endDate,
      interval: 'week',
      limit: 20,
      orderMode: 'asc',
      includeOther: true,
      // the stored filters, restricted to the relationships the widget displays
      filters: widgetRelationships(targets),
      dynamicFrom: malwares,
      dynamicTo: sectors,
      // the field is checked against the relationship types the filters restrict to
      relationship_type: ['targets'],
    });
    // Like the relationships time series, the displayed side of the widget plays no part
    expect(args).not.toHaveProperty('isTo');
  });

  it('should default the settings of the widget, and break all the relationships down without type filter', () => {
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at' }], { breakdownBy: 'relationship_type' });

    expect(relationshipsArgs(widget, { endDate: null })).toMatchObject({
      field: 'relationship_type',
      endDate: null,
      interval: 'day',
      limit: 10,
      orderMode: 'desc',
      includeOther: false,
      relationship_type: [],
    });
  });

  it('should only break the relationships the widgets display down, without relationship type filter', () => {
    // Without relationship type, every relationship would be broken down: the markings, the authors or the external
    // references of the elements too, which can fill the top values
    const notRevoked = { mode: 'and', filters: [{ key: ['revoked'], values: ['false'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    for (const filters of [undefined, notRevoked]) {
      const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters, dynamicFrom: malwares }], { breakdownBy: 'relationship_type' });

      expect(relationshipsArgs(widget)).toMatchObject({
        filters: widgetRelationships(filters),
        dynamicFrom: malwares,
        relationship_type: [],
      });
    }
  });

  it('should refuse a widget without breakdown, or a request without start date', () => {
    expect(() => relationshipsArgs(storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], { interval: 'day' })))
      .toThrow('This widget has no breakdown');
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
    expect(() => relationshipsArgs(widget, { startDate: null })).toThrow('A start date is required');
  });

  it('should refuse the widgets of the other perspectives, or without perspective, carrying a breakdown', () => {
    for (const perspective of ['entities', 'audits', null]) {
      const widget = storedWidget(perspective, [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
      expect(() => relationshipsArgs(widget)).toThrow('This widget has no breakdown');
    }
  });

  it('should refuse the widgets that cannot be broken down, still carrying a breakdown', () => {
    // Edited without the breakdown feature, or imported: the private dashboards draw their regular chart
    const relationships = { date_attribute: 'created_at', perspective: 'relationships', filters: targets };
    const stale = [
      { type: 'donut', dataSelection: [relationships] },
      { type: 'line', dataSelection: [relationships, relationships] },
      { type: 'line', dataSelection: [] },
      // a relationships widget can hold entities datasets, which cannot be broken down as relationships
      { type: 'vertical-bar', dataSelection: [{ ...relationships, perspective: 'entities', filters: malwares }] },
    ];
    for (const { type, dataSelection } of stale) {
      const widget = storedWidget('relationships', dataSelection, breakdownParameters, type);
      expect(() => relationshipsArgs(widget)).toThrow(expect.objectContaining({
        message: 'This widget cannot be broken down',
        extensions: expect.objectContaining({ code: 'FUNCTIONAL_ERROR' }),
      }));
    }
  });

  it('should break down every time series of a single relationships dataset', () => {
    for (const type of ['vertical-bar', 'line', 'area', 'heatmap']) {
      const widget = storedWidget('relationships', [{ date_attribute: 'created_at', perspective: 'relationships', filters: targets }], breakdownParameters, type);
      expect(relationshipsArgs(widget)).toMatchObject({ field: 'toTypes', relationship_type: ['targets'] });
    }
  });
});

describe('buildPublicBreakdownArgs of entities', () => {
  const entitiesArgs = (widget: unknown) => buildPublicBreakdownArgs(request(), widget as any, 'entities');

  it('should break the stored entities dataset down with the stored settings', () => {
    const reports = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    const widget = storedWidget('entities', [{ date_attribute: 'published', filters: reports }], { interval: 'month', breakdownBy: 'objectLabel', breakdownLimit: 5 });

    expect(entitiesArgs(widget)).toEqual({
      field: 'objectLabel',
      dateAttribute: 'published',
      startDate,
      endDate,
      interval: 'month',
      limit: 5,
      orderMode: 'desc',
      includeOther: false,
      filters: reports,
      // the field is checked against the types the filters restrict to
      types: ['Report'],
    });
  });

  it('should break every entity down without type filter', () => {
    const widget = storedWidget('entities', [{ date_attribute: 'created_at' }], { breakdownBy: 'entity_type' });
    expect(entitiesArgs(widget)).toMatchObject({ filters: undefined, types: ['Stix-Core-Object'] });
  });

  it('should refuse an audits widget carrying a breakdown', () => {
    const widget = storedWidget('audits', [{ date_attribute: 'timestamp', filters: null }], { interval: 'day', breakdownBy: 'event_scope', breakdownLimit: 5 });
    expect(() => entitiesArgs(widget)).toThrow('This widget has no breakdown');
  });

  it('should refuse the widgets of the other perspectives, or without perspective', () => {
    for (const perspective of ['relationships', null]) {
      const widget = storedWidget(perspective, [{ date_attribute: 'published', filters: null }], { interval: 'day', breakdownBy: 'objectLabel' });
      expect(() => entitiesArgs(widget)).toThrow('This widget has no breakdown');
    }
  });

  it('should refuse the entities widgets that cannot be broken down, still carrying a breakdown', () => {
    const entities = { date_attribute: 'published', perspective: 'entities', filters: malwares };
    const stale = [
      { type: 'number', dataSelection: [entities] },
      { type: 'area', dataSelection: [entities, entities] },
      { type: 'area', dataSelection: [{ ...entities, perspective: 'relationships' }] },
    ];
    for (const { type, dataSelection } of stale) {
      const widget = storedWidget('entities', dataSelection, { interval: 'day', breakdownBy: 'objectLabel' }, type);
      expect(() => entitiesArgs(widget)).toThrow(expect.objectContaining({
        message: 'This widget cannot be broken down',
        extensions: expect.objectContaining({ code: 'FUNCTIONAL_ERROR' }),
      }));
    }
  });
});

describe('getBreakdownEntityTypes', () => {
  const typeFilter = (values: string[], overrides: Record<string, unknown> = {}) => ({ key: ['entity_type'], values, operator: 'eq', mode: 'or', ...overrides });
  const notRevoked = { key: ['revoked'], values: ['false'], operator: 'eq', mode: 'or' };
  const group = (filters: unknown[], overrides: Record<string, unknown> = {}) => ({ mode: 'and', filters, filterGroups: [], ...overrides }) as any;

  it('should read the types of a top level type filter, whatever the form of its key', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware']), notRevoked]))).toEqual(['Report', 'Malware']);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { key: 'entity_type' })]))).toEqual(['Report']);
    // The relationship type of the relationships
    const relationshipTargets = typeFilter(['targets'], { key: ['relationship_type'] });
    expect(getBreakdownEntityTypes(group([relationshipTargets]), 'relationship_type')).toEqual(['targets']);
    expect(getBreakdownEntityTypes(group([relationshipTargets]))).toEqual([]);
  });

  it('should not restrict the types of a group in "or" with several entries', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report']), notRevoked], { mode: 'or' }))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or', filterGroups: [group([notRevoked])] }))).toEqual([]);
    // A single entry restricts the types whatever the mode of its group
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or' }))).toEqual(['Report']);
  });

  it('should not restrict the types of a type filter excluding them', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: 'not_eq' })]))).toEqual([]);
    // Without operator, a filter is an equality
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: undefined })]))).toEqual(['Report']);
  });

  it('should only read several types in "and" as no restriction, a single one restricts the type', () => {
    // Elements of every type at once
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware'], { mode: 'and' })]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { mode: 'and' })]))).toEqual(['Report']);
  });

  it('should read the stored filters missing a key', () => {
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'or', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'and', filterGroups: [] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', mode: 'or' }] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes(null)).toEqual([]);
  });
});
