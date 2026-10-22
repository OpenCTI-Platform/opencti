import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../../../utils/testQueryHelper';
import { STIX_EXT_OCTI } from '../../../../../src/types/stix-2-1-extensions';
import type { StixDomainObject } from '../../../../../src/types/stix-2-1-common';
import { PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT, type ManipulateConfiguration } from '../../../../../src/modules/playbook/components/manipulate-knowledge-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';

const CUSTOM_FIELD_ADD = gql`
  mutation PlaybookCustomFieldAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) { id }
  }
`;
const CUSTOM_FIELD_ADD_ENTITY_TYPE = gql`
  mutation PlaybookCustomFieldAddEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) { id }
  }
`;
const CUSTOM_FIELD_DELETE = gql`
  mutation PlaybookCustomFieldDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;
const MALWARE_ADD = gql`
  mutation PlaybookCustomFieldMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id standard_id }
  }
`;
const MALWARE_READ = gql`
  query PlaybookCustomFieldMalwareRead($id: String!) {
    malware(id: $id) { customFieldValues { field_name int_value string_value select_values } }
  }
`;
const MALWARE_DELETE = gql`
  mutation PlaybookCustomFieldMalwareDelete($id: ID!) {
    malwareEdit(id: $id) { delete }
  }
`;

const SCORE = 'x_opencti_cf_playbook_score';
const OWNER = 'x_opencti_cf_playbook_owner';
const SECTORS = 'x_opencti_cf_playbook_sectors';
const MALWARE_NAME = 'Playbook custom fields malware';

// Same conversion as the worker (pycti extract_custom_properties) for the custom properties of the OpenCTI extension
const toCustomFieldValues = (extension: Record<string, any>) => Object.entries(extension)
  .filter(([key]) => key.startsWith('x_opencti_cf_'))
  .map(([field_name, value]) => ({ field_name, value: Array.isArray(value) ? value : [value] }));

describe('PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT with custom fields', () => {
  const definitionIds: string[] = [];
  let malware: { id: string; standard_id: string };

  beforeAll(async () => {
    const definitions = [
      { name: SCORE, label: 'Playbook score', field_type: 'integer' },
      { name: OWNER, label: 'Playbook owner', field_type: 'string' },
      { name: SECTORS, label: 'Playbook sectors', field_type: 'multi_select', select_options: ['a', 'b', 'c'] },
    ];
    for (const input of definitions) {
      const added = await queryAsAdmin({ query: CUSTOM_FIELD_ADD, variables: { input: { description: `${input.label} description`, ...input } } });
      expect(added.errors).toBeUndefined();
      const { id } = added.data?.customFieldDefinitionAdd ?? {};
      await queryAsAdmin({ query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables: { id, entityType: 'Malware', mandatory: false } });
      definitionIds.push(id);
    }
    const created = await queryAsAdmin({
      query: MALWARE_ADD,
      variables: {
        input: {
          name: MALWARE_NAME,
          customFieldValues: [{ field_name: SCORE, value: [1] }, { field_name: OWNER, value: ['alice'] }, { field_name: SECTORS, value: ['a', 'b'] }],
        },
      },
    });
    expect(created.errors).toBeUndefined();
    malware = created.data?.malwareAdd;
  });

  afterAll(async () => {
    await queryAsAdmin({ query: MALWARE_DELETE, variables: { id: malware.id } });
    for (const id of definitionIds) {
      await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id } });
    }
  });

  it('should set, replace and clear custom field values of an existing entity', async () => {
    const element = testBundleObject<StixDomainObject>({
      id: malware.standard_id as StixDomainObject['id'],
      type: 'Malware',
      octiExtension: { id: malware.id, [SCORE]: 1, [OWNER]: 'alice', [SECTORS]: ['a', 'b'] } as any,
    });
    const configuration: ManipulateConfiguration = {
      applyToElements: 'only-main',
      actions: [
        { op: 'replace', attribute: SCORE, value: [{ label: '42', value: '42', patch_value: '42' }] },
        { op: 'remove', attribute: OWNER, value: [] },
        { op: 'replace', attribute: SECTORS, value: [{ label: 'c', value: 'c', patch_value: 'c' }] },
      ],
    };
    const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({ mainId: malware.standard_id, bundleObjects: [element], configuration }));
    expect(result.output_port).toBe('out');
    const extension = result.bundle.objects[0].extensions[STIX_EXT_OCTI] as Record<string, any>;
    expect(extension[SCORE]).toBe(42);
    expect(extension[OWNER]).toBeUndefined();
    expect(extension[SECTORS]).toEqual(['c']);

    // Ingest the element as the worker does: the upsert alone would keep the cleared field and the removed options
    const ingested = await queryAsAdmin({
      query: MALWARE_ADD,
      variables: {
        input: {
          name: MALWARE_NAME,
          stix_id: malware.standard_id,
          update: true,
          customFieldValues: toCustomFieldValues(extension),
          upsertOperations: extension.opencti_upsert_operations,
        },
      },
    });
    expect(ingested.errors).toBeUndefined();
    const read = await queryAsAdmin({ query: MALWARE_READ, variables: { id: malware.id } });
    const values = read.data?.malware.customFieldValues ?? [];
    expect(values).toHaveLength(2);
    expect(values).toEqual(expect.arrayContaining([
      expect.objectContaining({ field_name: SCORE, int_value: 42 }),
      expect.objectContaining({ field_name: SECTORS, select_values: ['c'] }),
    ]));
  });

  it('should add and remove multi_select options on the stored value, not on a stale bundle', async () => {
    // The stored options are ['c'] (previous test), the bundle still carries ['a']
    const element = testBundleObject<StixDomainObject>({
      id: malware.standard_id as StixDomainObject['id'],
      type: 'Malware',
      octiExtension: { id: malware.id, [SECTORS]: ['a'] } as any,
    });
    const configuration: ManipulateConfiguration = {
      applyToElements: 'only-main',
      actions: [
        { op: 'add', attribute: SECTORS, value: [{ label: 'b', value: 'b', patch_value: 'b' }] },
        { op: 'remove', attribute: SECTORS, value: [{ label: 'c', value: 'c', patch_value: 'c' }] },
      ],
    };
    const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({ mainId: malware.standard_id, bundleObjects: [element], configuration }));
    const extension = result.bundle.objects[0].extensions[STIX_EXT_OCTI] as Record<string, any>;
    const ingested = await queryAsAdmin({
      query: MALWARE_ADD,
      variables: {
        input: {
          name: MALWARE_NAME,
          stix_id: malware.standard_id,
          update: true,
          customFieldValues: toCustomFieldValues(extension),
          upsertOperations: extension.opencti_upsert_operations,
        },
      },
    });
    expect(ingested.errors).toBeUndefined();
    const read = await queryAsAdmin({ query: MALWARE_READ, variables: { id: malware.id } });
    const sectors = (read.data?.malware.customFieldValues ?? []).find((v: any) => v.field_name === SECTORS);
    expect(sectors?.select_values).toEqual(['b']);
  });
});
