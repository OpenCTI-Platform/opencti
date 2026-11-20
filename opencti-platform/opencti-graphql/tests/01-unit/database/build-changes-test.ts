import { describe, expect, it, vi } from 'vitest';
import { registerModules } from '../../../src/composition-root';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import { buildChanges } from '../../../src/database/data-changes';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../../src/modules/customField/custom-field-types';

registerModules();

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;

describe('buildChanges on multiple object attributes', () => {
  it('should compare objects whatever their key order', async () => {
    vi.spyOn(middlewareLoader, 'internalFindByIdsMapped').mockResolvedValue({
      'cf-1': { entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, name: 'x_opencti_cf_score', label: 'Risk score' },
      'cf-2': { entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, name: 'x_opencti_cf_note', label: 'Analyst note' },
    } as any);
    // Stored entries come back from elastic with another key order than the input
    const inputs = [{
      key: 'custom_field_values',
      previous: [
        { field_id: 'cf-1', int_value: 10, field_name: 'x_opencti_cf_score' },
        { field_id: 'cf-2', string_value: 'before', field_name: 'x_opencti_cf_note' },
      ],
      value: [
        { field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 10 },
        { field_id: 'cf-2', field_name: 'x_opencti_cf_note', string_value: 'after' },
      ],
    }];
    const changes = await buildChanges(CONTEXT, USER, ENTITY_TYPE_MALWARE, inputs);
    expect(changes).toEqual([{
      field: 'Malware--custom_field_values',
      changes_removed: [{
        raw: '{"field_id":"cf-2","string_value":"before","field_name":"x_opencti_cf_note"}',
        translated: '{"cf-2":"Analyst note"}',
      }],
      changes_added: [{
        raw: '{"field_id":"cf-2","field_name":"x_opencti_cf_note","string_value":"after"}',
        translated: '{"cf-2":"Analyst note"}',
      }],
    }]);
  });
});
