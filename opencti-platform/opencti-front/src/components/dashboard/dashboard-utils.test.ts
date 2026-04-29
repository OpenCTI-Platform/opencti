import { describe, it, expect } from 'vitest';
import { formatDate } from '../../utils/Time';
import { fromB64, toB64 } from '../../utils/String';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from './dashboard-utils';
import type { DashboardManifest, DashboardWidget } from './dashboard-types';
import { GqlFilterGroup, sanitizeFilterGroupKeysForBackend, sanitizeFilterGroupKeysForFrontend } from '../../utils/filters/filtersUtils';

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
              dynamicTo: sanitizeFilterGroupKeysForBackend(widget.dataSelection[0].dynamicTo!),
              dynamicFrom: sanitizeFilterGroupKeysForBackend(widget.dataSelection[0].dynamicFrom!),
              filters: sanitizeFilterGroupKeysForBackend(widget.dataSelection[0].filters!),
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
      const sanitizedFilterGroup = sanitizeFilterGroupKeysForFrontend(filterGroup);
      const expectedFilterGroup = {
        ...sanitizedFilterGroup,
        filters: sanitizedFilterGroup.filters.map((f) => ({
          ...f,
          id: expect.any(String),
        })),
        filterGroups: sanitizedFilterGroup.filterGroups.map((fg) => ({
          ...fg,
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
