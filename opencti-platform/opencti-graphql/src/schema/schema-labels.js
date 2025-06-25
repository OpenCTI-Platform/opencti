import { generateStandardId } from './identifier';
import { ENTITY_TYPE_LABEL } from './stixMetaObject';
import { isAnId } from './schemaUtils';

export const idLabel = (labelOrId, forceLabel = false) => {
  return (isAnId(labelOrId) && !forceLabel) ? labelOrId : generateStandardId(ENTITY_TYPE_LABEL, { value: labelOrId });
};
