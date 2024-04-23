import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_DELETE_OPERATION, type StixDeleteOperation, type StoreEntityDeleteOperation } from './deleteOperation-types';
import convertDeleteOperationToStix from './deleteOperation-converter';
import { confidence, createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import { objectMarking, objectOrganization } from '../../schema/stixRefRelationship';

const DELETE_OPERATION_DEFINITION: ModuleDefinition<StoreEntityDeleteOperation, StixDeleteOperation> = {
  type: {
    id: 'deleteOperation',
    name: ENTITY_TYPE_DELETE_OPERATION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DELETE_OPERATION]: () => uuidv4()
    },
  },
  attributes: [
    { ...updatedAt, isFilterable: false },
    { ...creators, label: 'Deleted by' },
    { ...createdAt, label: 'Deletion date' },
    confidence,
    { name: 'main_entity_type', label: 'Deleted entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'main_entity_id', label: 'Deleted entity id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'main_entity_name', label: 'Representation', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'deleted_elements', label: 'Deleted elements', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [objectOrganization, objectMarking],
  representative: (stix: StixDeleteOperation) => {
    return stix.main_entity_name;
  },
  converter: convertDeleteOperationToStix
};

registerDefinition(DELETE_OPERATION_DEFINITION);
