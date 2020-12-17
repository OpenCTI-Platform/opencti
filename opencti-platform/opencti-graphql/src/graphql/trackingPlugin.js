import { isNotEmptyField } from '../database/utils';
import { reportActionImport } from '../domain/work';
import { logger } from '../config/conf';

export default {
  requestDidStart: /* istanbul ignore next */ () => {
    return {
      willSendResponse: async (context) => {
        const isCallError = context.errors && context.errors.length > 0;
        const { user, workId } = context.context;
        if (!isCallError && isNotEmptyField(workId)) {
          try {
            await reportActionImport(user, workId);
          } catch (e) {
            logger.error(`Error updating figures for work ${workId}`, { error: e });
          }
        }
      },
    };
  },
};
