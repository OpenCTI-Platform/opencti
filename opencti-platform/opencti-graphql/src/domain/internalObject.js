import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { storeLoadById } from '../database/middleware-loader';
import {
  ABSTRACT_INTERNAL_OBJECT,
} from '../schema/general';

// region context
export const internalObjectCleanContext = async (context, user, internalObjectId) => {
  await delEditContext(user, internalObjectId);
  return storeLoadById(context, user, internalObjectId, ABSTRACT_INTERNAL_OBJECT).then((internalObject) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].CONTEXT_TOPIC, internalObject, user);
  });
};

export const internalObjectEditContext = async (context, user, internalObjectId, input) => {
  await setEditContext(user, internalObjectId, input);
  return storeLoadById(context, user, internalObjectId, ABSTRACT_INTERNAL_OBJECT).then((internalObject) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].CONTEXT_TOPIC, internalObject, user);
  });
};
// endregion
