import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { asStr, contains, getAttributeInExtension, required } from '../utils';
import { field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_marking_definition.py
const MARKING_DEFINITION_ADD = `
  mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput!) {
    markingDefinitionAdd(input: $input) { id standard_id entity_type parent_types definition_type definition x_opencti_order x_opencti_color }
  }
`;

// pycti opencti_marking_definition.py:create
const createMarkingDefinition = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'definition') === null || kw(kwargs, 'definition_type') === null) {
    context.logger.error('[opencti_marking_definition] Missing parameters: definition and definition_type');
    return null;
  }
  return mutate(context, MARKING_DEFINITION_ADD, 'markingDefinitionAdd', {
    definition_type: kw(kwargs, 'definition_type'),
    definition: kw(kwargs, 'definition'),
    x_opencti_order: kw(kwargs, 'x_opencti_order', 0),
    x_opencti_color: kw(kwargs, 'x_opencti_color'),
    stix_id: kw(kwargs, 'stix_id'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    update: kw(kwargs, 'update', false),
  });
};

// pycti opencti_marking_definition.py:import_from_stix2 (no extras: no author, labels, files...)
export const importMarkingDefinition = async (context: ImportContext, object: StixObject, _extras: Kwargs, update: boolean) => {
  let definitionType: any;
  let definition: any;
  if ('x_opencti_definition_type' in object && 'x_opencti_definition' in object) {
    definitionType = object.x_opencti_definition_type;
    definition = object.x_opencti_definition;
  } else if ('definition_type' in object) {
    definitionType = object.definition_type;
    definition = null;
    if (object.definition_type === 'tlp') {
      definitionType = definitionType.toUpperCase();
      if ('definition' in object) {
        definition = `${definitionType}:${asStr(required(object.definition, 'tlp'), 'upper').toUpperCase()}`;
      } else if ('name' in object) {
        definition = object.name;
      }
    } else if ('definition' in object) {
      const { definition: rawDefinition } = object;
      if (typeof rawDefinition === 'string') {
        definition = rawDefinition;
      } else if (rawDefinition !== null && typeof rawDefinition === 'object' && !Array.isArray(rawDefinition) && contains(rawDefinition, object.definition_type)) {
        definition = rawDefinition[object.definition_type];
      } else {
        definition = required(object, 'name');
      }
    } else if ('name' in object) {
      definition = object.name;
    }
  } else if ('name' in object) {
    definitionType = contains(object.name, ':') ? asStr(object.name, 'split').split(':')[0] : 'statement';
    definition = object.name;
  } else {
    return null;
  }
  if (definition === 'TLP:WHITE') {
    definition = 'TLP:CLEAR';
  }
  if (!('x_opencti_order' in object) && getAttributeInExtension('order', object) !== null) {
    object.x_opencti_order = getAttributeInExtension('order', object);
  }
  if (!('x_opencti_color' in object)) {
    object.x_opencti_color = getAttributeInExtension('color', object);
  }
  if (!('x_opencti_stix_ids' in object)) {
    object.x_opencti_stix_ids = getAttributeInExtension('stix_ids', object);
  }
  return createMarkingDefinition(context, {
    stix_id: object.id,
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    definition_type: definitionType,
    definition,
    x_opencti_order: field(object, 'x_opencti_order', 0),
    x_opencti_color: field(object, 'x_opencti_color'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    update,
  });
};
