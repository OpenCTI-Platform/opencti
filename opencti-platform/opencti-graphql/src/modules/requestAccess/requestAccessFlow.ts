import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_REQUEST_ACCESS_FLOW, type StixRequestAccessFlow, type StoreEntityRequestAccessFlow } from './requestAccessFlow-types';
import convertRequestAccessFlowToStix from './requestAccesFlow-converter';

const REQUEST_ACCESS_FLOW_DEFINITION: ModuleDefinition<StoreEntityRequestAccessFlow, StixRequestAccessFlow> = {
  type: {
    id: 'requestAccessFlow',
    name: ENTITY_TYPE_REQUEST_ACCESS_FLOW,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_REQUEST_ACCESS_FLOW]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'from', label: 'From', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'to', label: 'To', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'rfi_workflow_id', label: 'rfi_workflow_id', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixRequestAccessFlow) => {
    return `${stix.from}-${stix.to}`;
  },
  converter: convertRequestAccessFlowToStix
};

registerDefinition(REQUEST_ACCESS_FLOW_DEFINITION);
