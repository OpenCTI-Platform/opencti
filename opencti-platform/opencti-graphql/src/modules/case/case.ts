import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import convertCaseToStix from './case-converter';
import { ENTITY_TYPE_CONTAINER_CASE, type StixCase, type StoreEntityCase } from './case-types';
import { ENTITY_TYPE_CASE_TEMPLATE } from './case-template/case-template-types';

const CASE_DEFINITION: ModuleDefinition<StoreEntityCase, StixCase> = {
  type: {
    id: 'cases',
    name: ENTITY_TYPE_CONTAINER_CASE,
    category: ENTITY_TYPE_CONTAINER,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE]: [{ src: NAME_FIELD }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'caseTemplate', label: 'Case template', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_CASE_TEMPLATE], mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [objectOrganization],
  representative: (stix: StixCase) => {
    return stix.name;
  },
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
