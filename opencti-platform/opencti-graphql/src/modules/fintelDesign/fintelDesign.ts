import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_FINTEL_DESIGN } from './fintelDesign-types';
import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

export const FINTEL_DESIGN_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'fintelDesign',
    name: ENTITY_TYPE_FINTEL_DESIGN,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FINTEL_DESIGN]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    {
      name: 'file_id',
      label: 'File id',
      type: 'string',
      format: 'short',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    { name: 'gradiantFromColor', label: 'Gradiant From Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'gradiantToColor', label: 'Gradiant To Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'textColor', label: 'Text Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'default', label: 'Default', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
};

registerInternalObjectDefinition(FINTEL_DESIGN_DEFINITION);
