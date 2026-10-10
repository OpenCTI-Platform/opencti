import { describe, it, expect } from 'vitest';
import { formatDate } from '../../utils/Time';
import { fromB64, toB64 } from '../../utils/String';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from './dashboard-utils';
import type { DashboardManifest, DashboardWidget } from './dashboard-types';
import { GqlFilterGroup, normalizeFilterGroupForBackend, normalizeFilterGroupForFrontend } from '../../utils/filters/filtersUtils';

describe('dashboard serialization', () => {
  describe('serializeDashboardManifestForBackend', () => {
    it('serializes to a base-64 JSON.stringify\'d string and migrates filters to backend filters structure', () => {
      const widget: DashboardWidget = {
        id: '26672a6c-94de-4153-be20-b5bd2e813ec3',
        type: 'text',
        layout: {
          i: '26672a6c-94de-4153-be20-b5bd2e813ec3',
          h: 2,
          w: 1,
          x: 2,
          y: 3,
          moved: false,
          static: false,
        },
        dataSelection: [{
          perspective: 'entities',
          attribute: 'created_at',
          centerLat: null,
          centerLng: null,
          columns: [],
          date_attribute: null,
          dynamicFrom: {
            mode: 'or',
            filters: [
              { id: 'XX', key: 'value', values: ['value1'], operator: 'eq' },
              { key: 'name', values: ['name1, name2'] },
            ],
            filterGroups: [
              {
                mode: 'and',
                filters: [
                  { id: 'YY', key: 'name', values: [], operator: 'nil' },
                ],
                filterGroups: [],
              },
            ],
          },
          dynamicTo: {
            mode: 'or',
            filters: [
              { id: 'XX', key: 'value', values: ['value1'], operator: 'eq' },
              { key: 'name', values: ['name1, name2'] },
            ],
            filterGroups: [
              {
                mode: 'and',
                filters: [
                  { id: 'YY', key: 'name', values: [], operator: 'nil' },
                ],
                filterGroups: [],
              },
            ],
          },
          filters: {
            mode: 'or',
            filters: [
              { id: 'XX', key: 'value', values: ['value1'], operator: 'eq' },
              { key: 'name', values: ['name1, name2'] },
            ],
            filterGroups: [
              {
                mode: 'and',
                filters: [
                  { id: 'YY', key: 'name', values: [], operator: 'nil' },
                ],
                filterGroups: [],
              },
            ],
          },
          instance_id: null,
          isTo: false,
          label: 'some label',
          number: null,
        }],
      };
      const dashboard: DashboardManifest = {
        config: {
          startDate: formatDate(new Date('2025-04-29 10:31')),
          endDate: formatDate(new Date('2026-04-29 10:31')),
          relativeDate: null,
        },
        widgets: {
          [widget.id]: widget,
        },
      };
      const result = serializeDashboardManifestForBackend(dashboard);
      expect(typeof result).toBe('string');
      const parsedResult = JSON.parse(fromB64(result));
      expect(parsedResult).toStrictEqual({
        ...dashboard,
        widgets: {
          '26672a6c-94de-4153-be20-b5bd2e813ec3': {
            ...widget,
            dataSelection: [{
              ...widget.dataSelection[0],
              dynamicTo: normalizeFilterGroupForBackend(widget.dataSelection[0].dynamicTo!),
              dynamicFrom: normalizeFilterGroupForBackend(widget.dataSelection[0].dynamicFrom!),
              filters: normalizeFilterGroupForBackend(widget.dataSelection[0].filters!),
            }],
          },
        },
      });
    });
  });

  describe('deseri', () => {
    it('serializes to a base-64 JSON.stringify\'d string and migrates filters to backend filters structure', () => {
      const filterGroup: GqlFilterGroup = {
        mode: 'or',
        filters: [
          { key: ['value'], values: ['value1'], operator: 'eq' },
          { key: ['name'], values: ['name1, name2'] },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: ['name'], values: [], operator: 'nil' },
            ],
            filterGroups: [],
          },
        ],
      };
      const widget = {
        id: '26672a6c-94de-4153-be20-b5bd2e813ec3',
        type: 'text',
        layout: {
          i: '26672a6c-94de-4153-be20-b5bd2e813ec3',
          h: 2,
          w: 1,
          x: 2,
          y: 3,
          moved: false,
          static: false,
        },
        dataSelection: [{
          perspective: 'entities',
          attribute: 'created_at',
          centerLat: null,
          centerLng: null,
          columns: [],
          date_attribute: null,
          dynamicFrom: filterGroup,
          dynamicTo: filterGroup,
          filters: filterGroup,
          instance_id: null,
          isTo: false,
          label: 'some label',
          number: null,
        }],
      };
      const dashboard = {
        config: {
          startDate: formatDate(new Date('2025-04-29 10:31')),
          endDate: formatDate(new Date('2026-04-29 10:31')),
          relativeDate: null,
        },
        widgets: {
          [widget.id]: widget,
        },
      };
      const result = deserializeDashboardManifestForFrontend(toB64(JSON.stringify(dashboard)));
      expect(typeof result).toBe('object');
      const normalizedFilterGroup = normalizeFilterGroupForFrontend(filterGroup);
      const expectedFilterGroup = {
        ...normalizedFilterGroup,
        id: expect.any(String),
        filters: normalizedFilterGroup.filters.map((f) => ({
          ...f,
          id: expect.any(String),
        })),
        filterGroups: normalizedFilterGroup.filterGroups.map((fg) => ({
          ...fg,
          id: expect.any(String),
          filters: fg.filters.map((f) => ({ ...f, id: expect.any(String) })),
        })),
      };
      expect(result).toStrictEqual({
        ...dashboard,
        widgets: {
          '26672a6c-94de-4153-be20-b5bd2e813ec3': {
            ...widget,
            dataSelection: [{
              ...widget.dataSelection[0],
              dynamicFrom: expectedFilterGroup,
              dynamicTo: expectedFilterGroup,
              filters: expectedFilterGroup,
            }],
          },
        },
      });
    });
  });
});

describe('dashboard manifest with variables', () => {
  const backendRestriction = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };
  const variable = { id: 'v1', name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'filters', filters: backendRestriction }, defaultValue: 'sector-id' };

  it('should read a legacy manifest without variables identically', () => {
    const manifest = deserializeDashboardManifestForFrontend(toB64(JSON.stringify({ config: {}, widgets: {} })));
    expect(manifest).toEqual({ config: {}, widgets: {} });
    expect('variables' in manifest).toBe(false);
  });

  it('should round-trip an empty variables list', () => {
    const encoded = serializeDashboardManifestForBackend({ config: {}, widgets: {}, variables: [] });
    expect(JSON.parse(fromB64(encoded))).toEqual({ config: {}, widgets: {}, variables: [] });
    expect(deserializeDashboardManifestForFrontend(encoded)).toEqual({ config: {}, widgets: {}, variables: [] });
  });

  it('should normalize restriction filters in both directions', () => {
    const front = deserializeDashboardManifestForFrontend(toB64(JSON.stringify({ config: {}, widgets: {}, variables: [variable] })));
    const restriction = front.variables?.[0].restriction;
    expect(restriction?.mode).toEqual('filters');
    if (restriction?.mode !== 'filters') return;
    expect(restriction.filters.filters[0].key).toEqual('entity_type');
    const back = JSON.parse(fromB64(serializeDashboardManifestForBackend(front)));
    expect(back.variables[0].restriction.filters.filters[0].key).toEqual(['entity_type']);
    expect(back.variables[0]).toMatchObject({ id: 'v1', name: 'Sector', defaultValue: 'sector-id' });
  });

  it('should leave selection and none restrictions untouched', () => {
    const variables = [
      { id: 'v2', name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' },
      { id: 'v3', name: 'Pick', type: 'text', restriction: { mode: 'selection', values: ['a', 'b'] }, defaultValue: 'a' },
    ];
    const front = deserializeDashboardManifestForFrontend(toB64(JSON.stringify({ config: {}, widgets: {}, variables })));
    expect(front.variables).toEqual(variables);
  });
});
