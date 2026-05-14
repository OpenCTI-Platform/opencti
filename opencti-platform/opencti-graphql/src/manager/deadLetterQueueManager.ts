import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, consumeQueueWithAck, pushToWorkerForConnector } from '../database/rabbitmq';

const DEAD_LETTER_QUEUE_MANAGER_ENABLED = booleanConf('dead_letter_queue_manager:enabled', true);
const DEAD_LETTER_QUEUE_MANAGER_KEY = conf.get('dead_letter_queue_manager:lock_key') || 'dead_letter_queue_manager_lock';
const SCHEDULE_TIME = conf.get('dead_letter_queue_manager:interval') || 6000000; // 100 minutes default

/**
 * Consumes messages from the dead letter queue (too-large-bundle) one by one,
 * and re-publishes them to the original connector's worker queue.
 *
 * Each message contains a `rejection_info.original_connector_id` field
 * that identifies which connector originally produced the bundle.
 *
 * Messages are only acked if successfully re-routed.
 * If re-routing fails, the message is nacked and requeued.
 */
export const deadLetterQueueHandler = async () => {
  let successCount = 0;
  let errorCount = 0;

  try {
    await consumeQueueWithAck(CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, async (rawMessage: string) => {
      let data: any;
      try {
        data = JSON.parse(rawMessage);
      } catch (e: any) {
        logApp.error('[OPENCTI-MODULE] Dead letter queue manager - failed to parse message, nacking', {
          cause: e,
          manager: 'DEAD_LETTER_QUEUE_MANAGER',
        });
        errorCount += 1;
        return false; // nack and requeue
      }

      const originalConnectorId = data?.rejection_info?.original_connector_id;
      if (!originalConnectorId) {
        logApp.warn('[OPENCTI-MODULE] Dead letter queue message missing original_connector_id, nacking', {
          manager: 'DEAD_LETTER_QUEUE_MANAGER',
        });
        errorCount += 1;
        return false; // nack and requeue
      }

      try {
        // Remove rejection_info before re-sending to avoid infinite loops
        delete data.rejection_info;

        // Push the message back to the original connector's worker queue
        await pushToWorkerForConnector(originalConnectorId, data);
        successCount += 1;
        return true; // ack
      } catch (e: any) {
        logApp.error('[OPENCTI-MODULE] Dead letter queue manager - failed to reprocess message, nacking', {
          cause: e,
          manager: 'DEAD_LETTER_QUEUE_MANAGER',
          originalConnectorId,
        });
        errorCount += 1;
        return false; // nack and requeue
      }
    });
  } catch (e: any) {
    logApp.error('[OPENCTI-MODULE] Dead letter queue manager handling error', { cause: e, manager: 'DEAD_LETTER_QUEUE_MANAGER' });
  }

  if (successCount > 0 || errorCount > 0) {
    logApp.info(`[OPENCTI-MODULE] Dead letter queue manager completed: ${successCount} requeued, ${errorCount} errors`);
  }
};

const DEAD_LETTER_QUEUE_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'DEAD_LETTER_QUEUE_MANAGER',
  label: 'Dead letter queue manager',
  executionContext: 'dead_letter_queue_manager',
  cronSchedulerHandler: {
    handler: deadLetterQueueHandler,
    interval: SCHEDULE_TIME,
    lockKey: DEAD_LETTER_QUEUE_MANAGER_KEY,
  },
  enabledByConfig: DEAD_LETTER_QUEUE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(DEAD_LETTER_QUEUE_MANAGER_DEFINITION);
