import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import entityPlaybookResolvers from './playbook-resolvers';
import entityPlaybookTypeDefs from './playbook.graphql';
import { ENTITY_TYPE_PLAYBOOK, PlayComponentDefinition, StixPlaybook, StoreEntityPlaybook } from './playbook-types';
import convertEntityPlaybookToStix from './playbook-converter';

const ENTITY_PLAYBOOK_DEFINITION: ModuleDefinition<StoreEntityPlaybook, StixPlaybook> = {
  type: {
    id: 'playbook',
    name: ENTITY_TYPE_PLAYBOOK,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: entityPlaybookTypeDefs,
    resolver: entityPlaybookResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_PLAYBOOK]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: false },
    { name: 'playbook_running', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'playbook_start', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'playbook_definition', type: 'json', mandatoryType: 'internal', multiple: false, upsert: false, schemaDef: PlayComponentDefinition }
  ],
  relations: [],
  representative: (stix: StixPlaybook) => {
    return stix.name;
  },
  converter: convertEntityPlaybookToStix
};

registerDefinition(ENTITY_PLAYBOOK_DEFINITION);
