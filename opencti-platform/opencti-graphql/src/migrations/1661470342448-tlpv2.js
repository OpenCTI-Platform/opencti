import { SYSTEM_USER } from '../utils/access';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { addMarkingDefinition } from '../domain/markingDefinition';
import { MARKING_TLP_CLEAR } from '../schema/identifier';

export const up = async (next) => {
  await patchAttribute(
    SYSTEM_USER,
    `marking-definition--${MARKING_TLP_CLEAR}`,
    ENTITY_TYPE_MARKING_DEFINITION,
    { definition: 'TLP:CLEAR' }
  );
  await addMarkingDefinition(SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:AMBER+STRICT',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  next();
};

export const down = async (next) => {
  next();
};
