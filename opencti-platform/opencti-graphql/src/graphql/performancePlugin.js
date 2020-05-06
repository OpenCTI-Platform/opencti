import { isNil, isEmpty, filter } from 'ramda';
import { logger } from '../config/conf';

const innerCompute = (inners) => {
  return filter((i) => !isNil(i) && !isEmpty(i), inners).length;
};

export default {
  requestDidStart: /* istanbul ignore next */ () => {
    const start = Date.now();
    return {
      willSendResponse: (context) => {
        const stop = Date.now();
        const elapsed = stop - start;
        const size = Buffer.byteLength(JSON.stringify(context.request.variables));
        const isWrite = context.operation && context.operation.operation === 'mutation';
        let innerRelationCount = 0;
        if (isWrite) {
          // Try to identify if its an entity creation, and so count the number of underlying created relation
          const { input } = context.request.variables;
          if (input) {
            if (!isNil(input.createdByRef) && !isEmpty(input.createdByRef)) innerRelationCount += 1;
            if (!isNil(input.markingDefinitions)) innerRelationCount += innerCompute(input.markingDefinitions);
            if (!isNil(input.tags)) innerRelationCount += innerCompute(input.tags);
            if (!isNil(input.killChainPhases)) innerRelationCount += innerCompute(input.killChainPhases);
            if (!isNil(input.objectRefs)) innerRelationCount += innerCompute(input.objectRefs);
            if (!isNil(input.observableRefs)) innerRelationCount += innerCompute(input.observableRefs);
            if (!isNil(input.relationRefs)) innerRelationCount += innerCompute(input.relationRefs);
          }
        }
        const operationType = `${isWrite ? 'WRITE' : 'READ'}`;
        logger.info(`[PERF] API Call`, {
          type: operationType,
          operation: context.operation.name.value,
          time: elapsed,
          inner_relation_creation: innerRelationCount,
          size,
          errors: context.errors,
        });
      },
    };
  },
};
