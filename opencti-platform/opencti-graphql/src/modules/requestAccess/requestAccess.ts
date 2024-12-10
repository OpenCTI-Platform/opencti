import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_REQUEST_ACCESS, type StixRequestAccess, type StoreEntityRequestAccess } from './requestAccess-types';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { createdAt, creators } from '../../schema/attribute-definition';
import convertRequestAccessToStix from './requestAccess-converter';

const REQUEST_ACCESS_DEFINITION: ModuleDefinition<StoreEntityRequestAccess, StixRequestAccess> = {
  type: {
    id: 'requestAccess',
    name: ENTITY_TYPE_REQUEST_ACCESS,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_REQUEST_ACCESS]: () => uuidv4()
    },
  },
  attributes: [
    createdAt,
    creators,
    { name: 'name', label: 'Request Access Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'target_entities', label: 'Target Entities', type: 'string', format: 'id', entityTypes: [ABSTRACT_STIX_CORE_OBJECT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'target_memberships', label: 'Target Memberships', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_IDENTITY], mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixRequestAccess) => {
    return stix.name;
  },
  converter: convertRequestAccessToStix
};

registerDefinition(REQUEST_ACCESS_DEFINITION);
