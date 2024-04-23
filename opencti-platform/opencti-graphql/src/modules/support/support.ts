import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_SUPPORT_PACKAGE, type StixSupportPackage, type StoreEntitySupportPackage } from './support-types';
import convertSupportPackageToStix from './support-converter';

const SUPPORT_PACKAGE_DEFINITION: ModuleDefinition<StoreEntitySupportPackage, StixSupportPackage> = {
  type: {
    id: 'support-package',
    name: ENTITY_TYPE_SUPPORT_PACKAGE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SUPPORT_PACKAGE]: () => uuidv4()
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
      name: 'nodes_status',
      label: 'Package upload status on each node',
      type: 'object',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: false,
      format: 'flat'
    },
    {
      name: 'nodes_count',
      label: 'Number of nodes in cluster',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true
    }
  ],
  relations: [],
  representative: (instance: StixSupportPackage) => {
    return instance.name;
  },
  converter: convertSupportPackageToStix
};

registerDefinition(SUPPORT_PACKAGE_DEFINITION);
