// A procedure's components are observables linked to it by component-of relationships (component → procedure).
// Each relationship carries the component's position in the ordered sequence and whether it is Primary or Secondary.
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { RELATION_COMPONENT_OF } from '../../schema/stixCoreRelationship';
import { registerEntityValidator, type ValidatorFn } from '../../schema/validator-register';
import { FunctionalError } from '../../config/errors';

export const COMPONENT_TYPE_PRIMARY = 'primary';
export const COMPONENT_TYPE_SECONDARY = 'secondary';
export const ATTRIBUTE_COMPONENT_INDEX = 'component_index';
export const ATTRIBUTE_COMPONENT_TYPE = 'component_type';
export const FIRST_COMPONENT_PRIMARY_MESSAGE = 'The first component must be Primary.';

const componentIndex: AttributeDefinition = {
  name: ATTRIBUTE_COMPONENT_INDEX,
  label: 'Component index',
  type: 'numeric',
  precision: 'integer',
  mandatoryType: 'external',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: true,
};

const componentType: AttributeDefinition = {
  name: ATTRIBUTE_COMPONENT_TYPE,
  label: 'Component type',
  type: 'string',
  format: 'enum',
  values: [COMPONENT_TYPE_PRIMARY, COMPONENT_TYPE_SECONDARY],
  mandatoryType: 'external',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: true,
};

schemaAttributesDefinition.registerAttributes(RELATION_COMPONENT_OF, [componentIndex, componentType]);

// Edit inputs arrive as arrays of strings, creation inputs as plain values.
const single = (value: unknown) => (Array.isArray(value) ? value[0] : value);

const COMPONENT_TYPES = [COMPONENT_TYPE_PRIMARY, COMPONENT_TYPE_SECONDARY];

export const checkComponentPosition = (index: unknown, type: unknown) => {
  if (index === undefined || index === null) return;
  const position = Number(single(index));
  if (!Number.isInteger(position) || position < 0) {
    throw FunctionalError('The component index must be a whole number, 0 or higher.', { index });
  }
  if (!COMPONENT_TYPES.includes(single(type) as string)) {
    throw FunctionalError('The component type must be primary or secondary.', { type });
  }
  if (position === 0 && single(type) !== COMPONENT_TYPE_PRIMARY) {
    throw FunctionalError(FIRST_COMPONENT_PRIMARY_MESSAGE, { index, type });
  }
};

const validatorCreation: ValidatorFn = async (_context, _user, input) => {
  if (input[ATTRIBUTE_COMPONENT_INDEX] === undefined || input[ATTRIBUTE_COMPONENT_INDEX] === null || !input[ATTRIBUTE_COMPONENT_TYPE]) {
    throw FunctionalError('A component needs an index and a type.', { input });
  }
  checkComponentPosition(input[ATTRIBUTE_COMPONENT_INDEX], input[ATTRIBUTE_COMPONENT_TYPE]);
  return true;
};

const validatorUpdate: ValidatorFn = async (_context, _user, patch, initial) => {
  const index = patch[ATTRIBUTE_COMPONENT_INDEX] ?? initial?.[ATTRIBUTE_COMPONENT_INDEX];
  const type = patch[ATTRIBUTE_COMPONENT_TYPE] ?? initial?.[ATTRIBUTE_COMPONENT_TYPE];
  checkComponentPosition(index, type);
  return true;
};

registerEntityValidator(RELATION_COMPONENT_OF, { validatorCreation, validatorUpdate });
