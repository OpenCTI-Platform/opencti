import type { AuthContext } from '../../types/user';
import { connectorIdFromIngestId, queueDetails } from '../../domain/connector';
import { logApp } from '../../config/conf';
import { redisAddIngestionHistory, type ConnectorLog } from '../../database/redis';
import { patchAttribute } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { buildIngestFailureMessages, buildIngestSuccessMessages, type IngestionTypes, isMustExecuteIteration, updateBuiltInConnectorInfo } from './ingestionUtils';

// region Types
type DataHandlerFn = () => Promise<{ size: number; ingestionPatch: Record<string, any>; connectorInfo: Record<string, any> }>;
// endregion Types

export const ingestionQueueExecution = async (context: AuthContext, ingestion: IngestionTypes, dataHandlerFn: DataHandlerFn) => {
  const connectorId = connectorIdFromIngestId(ingestion.id);
  const { messages_number, messages_size } = await queueDetails(connectorId);
  // Some ingestion scheduling period can be adapted
  if (ingestion.kind === 'csv' || ingestion.kind === 'rss' || ingestion.kind === 'json') {
    if (!isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      // Too fast iteration for configuration, simply waiting
      return;
    }
  }
  // If ingestion have remaining messages in the queue don't fetch any new data
  if (messages_number > 0) {
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
    // await redisSetConnectorLogs(ingestion.internal_id, buildIngestQueueControlMessages());
    logApp.info('[OPENCTI-MODULE] Ingestion waiting', { name: ingestion.name, type: ingestion.entity_type, messages_number });
    return;
  }
  // Queue ready for a round trip
  try {
    const { size, connectorInfo, ingestionPatch } = await dataHandlerFn();
    const messages = buildIngestSuccessMessages(size);
    const patch = { ...ingestionPatch, last_execution_date: now(), last_execution_status: 'success' };
    await patchAttribute(context, SYSTEM_USER, ingestion.internal_id, ingestion.entity_type, patch);
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { ...connectorInfo, buffering: false });
    const historyLog: ConnectorLog = { timestamp: now(), messages, status: 'success' };
    await redisAddIngestionHistory(ingestion.internal_id, historyLog);
    logApp.info('[OPENCTI-MODULE] Ingestion execution success', { name: ingestion.name, type: ingestion.entity_type, messages });
  } catch (e: any) {
    const messages = buildIngestFailureMessages(e);
    const patch = { last_execution_date: now(), last_execution_status: 'error' };
    await patchAttribute(context, SYSTEM_USER, ingestion.internal_id, ingestion.entity_type, patch);
    const historyLog: ConnectorLog = { timestamp: now(), messages, status: 'error' };
    await redisAddIngestionHistory(ingestion.internal_id, historyLog);
    logApp.warn('[OPENCTI-MODULE] Ingestion execution fail', { cause: e, name: ingestion.name, type: ingestion.entity_type, messages });
  }
};
