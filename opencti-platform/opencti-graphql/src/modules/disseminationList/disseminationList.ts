import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_DISSEMINATION_LIST, type StixDisseminationList, type StoreEntityDisseminationList } from './disseminationList-types';
import convertDisseminationListToStix from './disseminationList-converter';

const DISSEMINATION_LIST_DEFINITION: ModuleDefinition<StoreEntityDisseminationList, StixDisseminationList> = {
  type: {
    id: 'disseminationList',
    name: ENTITY_TYPE_DISSEMINATION_LIST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DISSEMINATION_LIST]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'emails', label: 'Emails', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDisseminationList) => {
    return stix.name;
  },
  converter: convertDisseminationListToStix
};

registerDefinition(DISSEMINATION_LIST_DEFINITION);
