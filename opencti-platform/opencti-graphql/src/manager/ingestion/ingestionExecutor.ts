import type { AuthContext } from '../../types/user';
import { connectorIdFromIngestId, queueDetails } from '../../domain/connector';
import { logApp } from '../../config/conf';
import { redisSetConnectorLogs } from '../../database/redis';
import { patchAttribute } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import {
  buildIngestFailureMessages,
  buildIngestQueueControlMessages,
  buildIngestSuccessMessages,
  type IngestionTypes,
  isMustExecuteIteration,
  updateBuiltInConnectorInfo
} from './ingestionUtils';

type DataHandlerFn = () => Promise<{ size: number, ingestionPatch: object, connectorInfo: object }>;
export const ingestionQueueExecution = async (context: AuthContext, ingestion: IngestionTypes, dataHandlerFn: DataHandlerFn) => {
  const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
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
    await redisSetConnectorLogs(ingestion.internal_id, buildIngestQueueControlMessages());
    logApp.info('[OPENCTI-MODULE] Ingestion waiting', { name: ingestion.name, type: ingestion.entity_type, messages_number });
    return;
  }
  // Queue ready for a round trip
  try {
    const { size, connectorInfo, ingestionPatch } = await dataHandlerFn();
    const messages = buildIngestSuccessMessages(size);
    await patchAttribute(context, SYSTEM_USER, ingestion.internal_id, ingestion.entity_type, ingestionPatch);
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { ...connectorInfo, buffering: false });
    await redisSetConnectorLogs(ingestion.internal_id, messages);
    logApp.info('[OPENCTI-MODULE] Ingestion execution success', { name: ingestion.name, type: ingestion.entity_type, messages });
  } catch (e: any) {
    const messages = buildIngestFailureMessages(e);
    await patchAttribute(context, SYSTEM_USER, ingestion.internal_id, ingestion.entity_type, { last_execution_date: now() });
    await redisSetConnectorLogs(ingestion.internal_id, messages);
    logApp.warn('[OPENCTI-MODULE] Ingestion execution fail', { cause: e, name: ingestion.name, type: ingestion.entity_type, messages });
  }
};
