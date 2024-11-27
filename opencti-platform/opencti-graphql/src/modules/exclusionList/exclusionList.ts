import convertExclusionListToStix from './exclusionList-converter';
import { ENTITY_TYPE_EXCLUSION_LIST, type StixExclusionList, type StoreEntityExclusionList } from './exclusionList-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { isFeatureEnabled } from '../../config/conf';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';

const EXCLUSION_LIST_DEFINITION: ModuleDefinition<StoreEntityExclusionList, StixExclusionList> = {
  type: {
    id: 'exclusion-list',
    name: ENTITY_TYPE_EXCLUSION_LIST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_EXCLUSION_LIST]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      }
    },
  },
  attributes: [
    {
      name: 'name',
      label: 'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true
    },
    {
      name: 'description',
      label: 'Description',
      type: 'string',
      format: 'text',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false
    },
    {
      name: 'enabled',
      label: 'Enabled',
      type: 'boolean',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true
    },
    {
      name: 'exclusion_list_entity_types',
      label: 'Exclusion list entity types',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true
    },
    {
      name: 'file_id',
      label: 'File id',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false
    }
  ],
  relations: [],
  representative: (instance: StixExclusionList) => {
    return instance.name;
  },
  converter: convertExclusionListToStix
};

const isExclusionListEnabled = isFeatureEnabled('EXCLUSION_LIST');

if (isExclusionListEnabled) {
  registerDefinition(EXCLUSION_LIST_DEFINITION);
}
