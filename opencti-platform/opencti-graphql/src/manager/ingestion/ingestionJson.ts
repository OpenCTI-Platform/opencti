import type { BasicStoreEntityIngestionJson, DataParam } from '../../modules/ingestion/ingestion-types';
import { isNotEmptyField } from '../../database/utils';
import type { AuthContext } from '../../types/user';
import { executeJsonQuery, findAllJsonIngestion } from '../../modules/ingestion/ingestion-json-domain';
import { now } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { pushBundleToConnectorQueue } from './ingestionUtils';
import { ingestionQueueExecution } from './ingestionExecutor';

const mergeQueryState = (queryParamsAttributes: Array<DataParam> | undefined, previousState: Record<string, any>, newState: Record<string, any>) => {
  const state: Record<string, any> = {};
  const queryParams = queryParamsAttributes ?? [];
  for (let attrIndex = 0; attrIndex < queryParams.length; attrIndex += 1) {
    const queryParamsAttribute = queryParams[attrIndex];
    if (queryParamsAttribute.state_operation === 'sum') {
      state[queryParamsAttribute.to] = parseInt(previousState[queryParamsAttribute.to] ?? 0, 10) + parseInt(newState[queryParamsAttribute.to] ?? 0, 10);
    } else {
      state[queryParamsAttribute.to] = isNotEmptyField(newState[queryParamsAttribute.to]) ? newState[queryParamsAttribute.to] : previousState[queryParamsAttribute.to];
    }
  }
  return state;
};

const jsonDataHandler = async (context: AuthContext, ingestion: BasicStoreEntityIngestionJson) => {
  const { bundle, variables, nextExecutionState } = await executeJsonQuery(context, ingestion);
  // Push the bundle to absorption queue if required
  if (bundle.objects.length > 0) {
    await pushBundleToConnectorQueue(context, ingestion, bundle);
  }
  // Save new state for next execution
  const ingestionState = mergeQueryState(ingestion.query_attributes, variables, nextExecutionState);
  const state = { ingestion_json_state: ingestionState, last_execution_date: now() };
  return { size: bundle.objects.length, ingestionPatch: state, connectorInfo: { state: ingestionState } };
};

export const jsonExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true };
  const ingestions = await findAllJsonIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const dataHandlerFn = () => jsonDataHandler(context, ingestion);
    ingestionPromises.push(ingestionQueueExecution(context, ingestion, dataHandlerFn));
  }
  return Promise.all(ingestionPromises);
};
