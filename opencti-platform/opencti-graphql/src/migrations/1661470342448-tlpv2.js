import { executionContext, SYSTEM_USER } from '../utils/access';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { addAllowedMarkingDefinition } from '../domain/markingDefinition';
import { MARKING_TLP_CLEAR } from '../schema/identifier';
import { internalLoadById } from '../database/middleware-loader';

export const up = async (next) => {
  const context = executionContext('migration');
  const markingId = `marking-definition--${MARKING_TLP_CLEAR}`;
  const whiteMarking = await internalLoadById(context, SYSTEM_USER, markingId);
  if (whiteMarking) { // Could be deleted on some platforms
    await patchAttribute(context, SYSTEM_USER, markingId, ENTITY_TYPE_MARKING_DEFINITION, { definition: 'TLP:CLEAR' });
  }
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
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
