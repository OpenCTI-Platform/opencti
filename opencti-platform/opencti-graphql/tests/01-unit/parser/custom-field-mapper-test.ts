import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cacheModule from '../../../src/database/cache';
import { mappingProcess } from '../../../src/parser/csv-mapper';
import jsonMappingExecution from '../../../src/parser/json-mapper';
import { CsvMapperRepresentationType, type CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../../src/modules/customField/custom-field-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const definitions = [
  { id: 'cf-score', name: 'x_opencti_cf_score', label: 'Score', field_type: 'integer', entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT] },
  { id: 'cf-tags', name: 'x_opencti_cf_tags', label: 'Tags', field_type: 'multi_select', select_options: ['a', 'b', 'c'], entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT] },
  { id: 'cf-flag', name: 'x_opencti_cf_flag', label: 'Flag', field_type: 'boolean', entity_types: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT] },
];

describe('Mappers with custom fields', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockImplementation(async (_, __, type) => (
      type === ENTITY_TYPE_CUSTOM_FIELD_DEFINITION ? definitions : []
    ) as any);
  });

  it('should map CSV columns to custom fields', async () => {
    const mapper = {
      has_header: false,
      separator: ',',
      representations: [{
        id: 'representation-case',
        type: CsvMapperRepresentationType.Entity,
        target: { entity_type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT },
        attributes: [
          { key: 'name', column: { column_name: 'A' } },
          { key: 'x_opencti_cf_score', column: { column_name: 'B' } },
          { key: 'x_opencti_cf_tags', column: { column_name: 'C', configuration: { separator: '|' } } },
          { key: 'x_opencti_cf_flag', column: { column_name: 'D' } },
        ],
      }],
    } as unknown as CsvMapperParsed;
    const [input] = await mappingProcess(testContext, ADMIN_USER, mapper, ['Case from csv', '42', 'a|b', 'yes'], {});
    expect(input.name).toEqual('Case from csv');
    expect(input.x_opencti_cf_score).toBeUndefined();
    expect(input.custom_field_values).toEqual([
      { field_id: 'cf-score', field_name: 'x_opencti_cf_score', int_value: 42 },
      { field_id: 'cf-tags', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] },
      { field_id: 'cf-flag', field_name: 'x_opencti_cf_flag', boolean_value: true },
    ]);
  });

  it('should map JSON paths to custom fields', async () => {
    const mapper: Partial<JsonMapperParsed> = {
      type: 'jsonMapper',
      name: 'cases',
      variables: [],
      representations: [{
        id: 'representation-case',
        type: JsonMapperRepresentationType.Entity,
        target: { entity_type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT, path: '$[*]' },
        identifier: undefined,
        attributes: [
          { mode: 'simple', key: 'name', attr_path: { path: '$.name' } },
          { mode: 'simple', key: 'x_opencti_cf_score', attr_path: { path: '$.score' } },
        ],
      }],
    };
    const objects = await jsonMappingExecution(testContext, ADMIN_USER, '[{ "name": "Case from json", "score": 7 }]', mapper as JsonMapperParsed);
    const caseIncident = objects.find((o: any) => o.name === 'Case from json') as any;
    expect(caseIncident.extensions[STIX_EXT_OCTI].x_opencti_cf_score).toEqual(7);
  });
});
