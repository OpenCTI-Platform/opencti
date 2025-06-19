import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_FINTEL_DESIGN, type StixFintelDesign, type StoreEntityFintelDesign } from './fintelDesign-types';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { convertFintelDesignToStix } from './fintelDesign-converter';

export const FINTEL_DESIGN_DEFINITION: ModuleDefinition<StoreEntityFintelDesign, StixFintelDesign> = {
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
      isFilterable: false
    },
    { name: 'gradiantFromColor', label: 'Gradiant From Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'gradiantToColor', label: 'Gradiant To Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'textColor', label: 'Text Color', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixFintelDesign) => {
    return stix.name;
  },
  converter_2_1: convertFintelDesignToStix
};

registerDefinition(FINTEL_DESIGN_DEFINITION);
