import { v4 as uuidv4 } from 'uuid';
import { registerDefinition } from '../../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { ENTITY_TYPE_CASE_TEMPLATE, TEMPLATE_TASK_RELATION } from './case-template-types';
import convertCaseTemplateToStix from './case-template-converter';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../../task/task-template/task-template-types';
const CaseTemplateToTaskTemplateRelation = {
    name: 'tasks',
    type: 'ref',
    databaseName: TEMPLATE_TASK_RELATION,
    label: 'Tasks',
    stixName: 'task_refs',
    mandatoryType: 'internal',
    editDefault: false,
    multiple: true,
    checker: (_, toType) => toType === ENTITY_TYPE_TASK_TEMPLATE,
    datable: false,
    upsert: true,
    isFilterable: true,
};
const CASE_TEMPLATE_DEFINITION = {
    type: {
        id: 'case-template',
        name: ENTITY_TYPE_CASE_TEMPLATE,
        category: ABSTRACT_INTERNAL_OBJECT
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CASE_TEMPLATE]: () => uuidv4(),
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    relationsRefs: [CaseTemplateToTaskTemplateRelation],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertCaseTemplateToStix
};
registerDefinition(CASE_TEMPLATE_DEFINITION);
