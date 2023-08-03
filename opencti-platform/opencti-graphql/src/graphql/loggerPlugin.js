import { filter, head, includes, isEmpty, isNil } from 'ramda';
import { stripIgnoredCharacters } from 'graphql/utilities';
import conf, { appLogExtendedErrors, booleanConf, logApp } from '../config/conf';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { getMemoryStatistics } from '../domain/settings';
import { ALREADY_DELETED_ERROR, AUTH_REQUIRED, FORBIDDEN_ACCESS, UNSUPPORTED_ERROR, VALIDATION_ERROR } from '../config/errors';
import { publishUserAction } from '../listener/UserActionListener';

const innerCompute = (inners) => {
  return filter((i) => !isNil(i) && !isEmpty(i), inners).length;
};

const API_CALL_MESSAGE = 'GRAPHQL_API'; // If you touch this, you need to change the performance agent
const perfLog = booleanConf('app:performance_logger', false);
const LOGS_SENSITIVE_FIELDS = conf.get('app:app_logs:logs_redacted_inputs') ?? [];

const graphQLNodeParser = (node) => {
  const result = [];
  try {
    if (node.kind === 'Field') {
      const data = { name: node.name?.value, alias: node.alias?.value };
      data.arguments = (node.arguments ?? []).map((arg) => graphQLNodeParser(arg));
      result.push(data);
    }
    if (node.kind === 'Argument') {
      const data = { name: node.name.value, alias: node.alias?.value };
      if (node.value.kind === 'ObjectValue' || node.value.kind === 'ObjectField') {
        data.value = graphQLNodeParser(node.value);
      } else { // Direct value
        data.type = node.value.kind;
        data.is_empty = data.type === 'ListValue' ? isEmptyField(node.value.values) : isEmptyField(node.value.value);
      }
      result.push(data);
    }
    if (node.kind === 'ObjectField') {
      const data = { name: node.name.value, alias: node.alias?.value };
      data.type = node.value.kind;
      data.is_empty = data.type === 'ListValue' ? isEmptyField(node.value.values) : isEmptyField(node.value.value);
      result.push(data);
    }
    if (node.kind === 'ObjectValue') {
      const data = { values: (node.fields ?? []).map((arg) => graphQLNodeParser(arg)) };
      result.push(data);
    }
  } catch {
    // Node fail to be parsed
  }
  return result;
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

export default {
  requestDidStart: /* v8 ignore next */ () => {
    const start = Date.now();
    return {
      willSendResponse: async (context) => {
        const stop = Date.now();
        const elapsed = stop - start;
        const isCallError = context.errors && context.errors.length > 0;
        if (!isCallError && !perfLog) {
          return;
        }
        const contextVariables = context.request.variables || {};
        const size = Buffer.byteLength(JSON.stringify(contextVariables));
        const isWrite = context.operation && context.operation.operation === 'mutation';
        const contextUser = context.contextValue.user;
        const origin = contextUser ? contextUser.origin : undefined;
        const [variables] = await tryResolveKeyPromises(contextVariables);
        // Compute inner relations
        let innerRelationCount = 0;
        if (isWrite) {
          const { input } = contextVariables;
          if (input) {
            // Inner relation counting
            if (!isNil(input.createdBy) && !isEmpty(input.createdBy)) innerRelationCount += 1;
            if (!isNil(input.markingDefinitions)) innerRelationCount += innerCompute(input.markingDefinitions);
            if (!isNil(input.labels)) innerRelationCount += innerCompute(input.labels);
            if (!isNil(input.killChainPhases)) innerRelationCount += innerCompute(input.killChainPhases);
            if (!isNil(input.objectRefs)) innerRelationCount += innerCompute(input.objectRefs);
            if (!isNil(input.observableRefs)) innerRelationCount += innerCompute(input.observableRefs);
            if (!isNil(input.relationRefs)) innerRelationCount += innerCompute(input.relationRefs);
            // Anonymization of sensitive data
            LOGS_SENSITIVE_FIELDS.forEach((field) => {
              if (isNotEmptyField(input[field])) {
                input[field] = '** Redacted **';
              }
            });
          }
        }
        const operationType = `${isWrite ? 'WRITE' : 'READ'}`;
        const callMetaData = {
          user: origin,
          type: operationType + (isCallError ? '_ERROR' : ''),
          inner_relation_creation: innerRelationCount,
          operation: context.request.operationName ?? 'Unspecified',
          time: elapsed,
          size,
        };
        if (isCallError) {
          const currentError = head(context.errors);
          if (appLogExtendedErrors) {
            callMetaData.variables = variables;
            callMetaData.operation_query = stripIgnoredCharacters(context.request.query);
          } else {
            callMetaData.query_attributes = (currentError.nodes ?? []).map((node) => graphQLNodeParser(node));
          }
          const callError = currentError.originalError ? currentError.originalError : currentError;
          const isRetryableCall = isNotEmptyField(origin?.call_retry_number) && ![
            UNSUPPORTED_ERROR,
            ALREADY_DELETED_ERROR,
            VALIDATION_ERROR,
          ].includes(callError.name);
          const isAuthenticationCall = includes(callError.name, [AUTH_REQUIRED]);
          // Don't log for a simple missing authentication
          if (isAuthenticationCall) {
            return;
          }
          // Authentication problem can be logged in warning (dissoc variables to hide password)
          // If worker is still retrying, this is not yet a problem, can be logged in warning until then.
          if (isRetryableCall) {
            logApp.warn(callError, callMetaData);
          } else if (callError.name === FORBIDDEN_ACCESS) {
            await publishUserAction({
              user: contextUser,
              event_type: isWrite ? 'mutation' : 'read',
              event_scope: 'unauthorized',
              event_access: 'administration',
              status: 'error',
              context_data: {
                operation: context.operationName,
                input: context.request.variables,
              }
            });
          } else {
            // Every other uses cases are logged with error level
            logApp.error(callError, callMetaData);
          }
        } else if (perfLog) {
          logApp.info(API_CALL_MESSAGE, { ...callMetaData, memory: getMemoryStatistics() });
        }
      },
    };
  },
};
