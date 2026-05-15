import convertDraftEntityReadToStix from './draftEntityRead-converter';
import { ENTITY_TYPE_DRAFT_ENTITY_READ, type StoreEntityDraftEntityRead, type StixDraftEntityRead } from './draftEntityRead-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { createdAt } from '../../schema/attribute-definition';

const DRAFT_ENTITY_READ_DEFINITION: ModuleDefinition<StoreEntityDraftEntityRead, StixDraftEntityRead> = {
  type: {
    id: 'draft-entity-read',
    name: ENTITY_TYPE_DRAFT_ENTITY_READ,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DRAFT_ENTITY_READ]: [{ src: 'user_id' }, { src: 'draft_id' }, { src: 'entity_id' }],
    },
  },
  attributes: [
    createdAt,
    {
      name: 'user_id',
      label: 'User',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'draft_id',
      label: 'Draft',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'entity_id',
      label: 'Entity',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'is_read',
      label: 'Is read',
      type: 'boolean',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
  ],
  relations: [],
  representative: (instance: StixDraftEntityRead) => {
    return `${instance.user_id}/${instance.entity_id}`;
  },
  converter_2_1: convertDraftEntityReadToStix,
};

registerDefinition(DRAFT_ENTITY_READ_DEFINITION);
