import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../schema/module';
import { ENTITY_TYPE_SUPPORT_PACKAGE } from './support-types';

const SUPPORT_PACKAGE_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'support-package',
    name: ENTITY_TYPE_SUPPORT_PACKAGE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SUPPORT_PACKAGE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name',
      label:
          'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true },
    { name: 'package_status',
      label: 'Package status',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true },
    { name: 'package_url',
      label: 'Package url',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false },
    { name: 'package_upload_dir',
      label: 'Package upload directory',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false },
    {
      name: 'nodes_count',
      label: 'Number of nodes in cluster',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
  ],
  relations: [],
};

registerInternalObjectDefinition(SUPPORT_PACKAGE_DEFINITION);
