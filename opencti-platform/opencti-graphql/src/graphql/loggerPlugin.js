import { dissoc, filter, head, includes, isEmpty, isNil } from 'ramda';
import { stripIgnoredCharacters } from 'graphql';
import nconf from 'nconf';
import { logger } from '../config/conf';
import { isNotEmptyField } from '../database/utils';
import { getMemoryStatistics } from '../domain/settings';

const innerCompute = (inners) => {
  return filter((i) => !isNil(i) && !isEmpty(i), inners).length;
};

const resolveKeyPromises = async (object) => {
  const resolvedObject = {};
  const entries = Object.entries(object).filter(([, value]) => value && typeof value.then === 'function');
  const values = await Promise.all(entries.map(([, value]) => value));
  entries.forEach(([key], index) => {
    resolvedObject[key] = values[index];
  });
  return { ...object, ...resolvedObject };
};

const tryResolveKeyPromises = async (data) => {
  try {
    return [await resolveKeyPromises(data), undefined];
  } catch (e) {
    return [data, e];
  }
};

const API_CALL_MESSAGE = 'API Call'; // If you touch this, you need to change the performance agent
const perfLog = nconf.get('app:performance_logger') || false;
export default {
  requestDidStart: /* istanbul ignore next */ () => {
    const start = Date.now();
    let op;
    return {
      didResolveOperation: (context) => {
        op = context.operationName;
      },
      willSendResponse: async (context) => {
        const stop = Date.now();
        const elapsed = stop - start;
        const size = Buffer.byteLength(JSON.stringify(context.request.variables));
        const isWrite = context.operation && context.operation.operation === 'mutation';
        const contextUser = context.context.user;
        const origin = contextUser ? contextUser.origin : undefined;
        const [variables] = await tryResolveKeyPromises(context.request.variables);
        const isCallError = context.errors && context.errors.length > 0;
        // Compute inner relations
        let innerRelationCount = 0;
        if (isWrite) {
          const { input } = context.request.variables;
          if (input) {
            if (!isNil(input.createdBy) && !isEmpty(input.createdBy)) innerRelationCount += 1;
            if (!isNil(input.markingDefinitions)) innerRelationCount += innerCompute(input.markingDefinitions);
            if (!isNil(input.labels)) innerRelationCount += innerCompute(input.labels);
            if (!isNil(input.killChainPhases)) innerRelationCount += innerCompute(input.killChainPhases);
            if (!isNil(input.objectRefs)) innerRelationCount += innerCompute(input.objectRefs);
            if (!isNil(input.observableRefs)) innerRelationCount += innerCompute(input.observableRefs);
            if (!isNil(input.relationRefs)) innerRelationCount += innerCompute(input.relationRefs);
          }
        }
        const operationType = `${isWrite ? 'WRITE' : 'READ'}`;
        const callMetaData = {
          user: origin,
          type: operationType + (isCallError ? '_ERROR' : ''),
          operation_query: stripIgnoredCharacters(context.request.query),
          inner_relation_creation: innerRelationCount,
          operation: op || 'Unspecified',
          time: elapsed,
          variables,
          size,
        };
        if (isCallError) {
          const currentError = head(context.errors);
          const callError = currentError.originalError ? currentError.originalError : currentError;
          const { data, path, stack } = callError;
          const error = { data, path, stacktrace: stack.split('\n').map((line) => line.trim()) };
          const isRetryableCall = isNotEmptyField(origin?.call_retry_number);
          const isAuthenticationCall = includes(callError.name, ['AuthRequired', 'AuthFailure', 'ForbiddenAccess']);
          // Authentication problem can be logged in warning (dissoc variables to hide password)
          // If worker is still retrying, this is not yet a problem, can be logged in warning until then.
          if (isRetryableCall || isAuthenticationCall) {
            logger.warn(API_CALL_MESSAGE, { ...dissoc('variables', callMetaData), error });
          } else {
            // Every other uses cases are logged with error level
            logger.error(API_CALL_MESSAGE, { ...callMetaData, error });
          }
        } else if (perfLog) {
          logger.info(API_CALL_MESSAGE, { ...callMetaData, memory: getMemoryStatistics() });
        }
      },
    };
  },
};
