import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityDeadLetterMessage, ENTITY_TYPE_DEAD_LETTER_MESSAGE } from './deadLetterMessage-types';
import type { QueryDeadLetterMessagesArgs } from '../../generated/graphql';
import { CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, consumeMessages, getConnectorQueueSize, pushToConnector } from '../../database/rabbitmq';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { deleteFileFromStorage, getFileContent, rawUpload } from '../../database/raw-file-storage';
import { logApp } from '../../config/conf';
import type { StoreEntityDeadLetterMessage } from './deadLetterMessage-types';

const LOG_PREFIX = '[DEAD_LETTER]';

export const getDeadLetterQueueMessageCount = async (context: AuthContext, user: AuthUser) => {
  return getConnectorQueueSize(context, user, CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID);
};

export const findById = async (context: AuthContext, user: AuthUser, deadLetterId: string) => {
  return storeLoadById(context, user, deadLetterId, ENTITY_TYPE_DEAD_LETTER_MESSAGE) as unknown as BasicStoreEntityDeadLetterMessage;
};

export const findDeadLetterPaginated = async (context: AuthContext, user: AuthUser, opts: QueryDeadLetterMessagesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDeadLetterMessage>(context, user, [ENTITY_TYPE_DEAD_LETTER_MESSAGE], opts);
};

export const deleteDeadLetterMessage = async (context: AuthContext, user: AuthUser, deadLetterId: string) => {
  const deadLetterMessage = await findById(context, user, deadLetterId);
  if (!deadLetterMessage) {
    return deadLetterId;
  }
  await deleteFileFromStorage(deadLetterMessage.file_id);
  return deleteInternalObject(context, user, deadLetterId, ENTITY_TYPE_DEAD_LETTER_MESSAGE);
};

const processDeadLetterMessage = async (context: AuthContext, user: AuthUser, rawContent: string) => {
  const parsedMessage = JSON.parse(rawContent);
  // Decode the base64-encoded content to extract original_connector_id and rejection_info
  const decodedContent = Buffer.from(parsedMessage.content, 'base64').toString('utf-8');
  const contentObject = JSON.parse(decodedContent);
  const rejectionInfo = contentObject.rejection_info ?? {};
  const { original_connector_id, ...finalRejectionInfo } = rejectionInfo;
  const deadLetterMessageId = uuidv4();
  // Upload the full raw message to S3
  const fileId = `dead-letter-messages/${deadLetterMessageId}.json`;
  await rawUpload(fileId, rawContent);
  // Create the DeadLetterMessage internal entity
  const input = {
    internal_id: deadLetterMessageId,
    file_id: fileId,
    original_connector_id,
    rejection_info: finalRejectionInfo,
  };
  await createInternalObject<StoreEntityDeadLetterMessage>(
    context,
    user,
    input,
    ENTITY_TYPE_DEAD_LETTER_MESSAGE,
  );
};

export const importDeadLetterMessages = async (context: AuthContext, user: AuthUser) => {
  await consumeMessages(CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, async (message: string) => {
    try {
      await processDeadLetterMessage(context, user, message);
    } catch (err) {
      logApp.error(`${LOG_PREFIX} Failed to import dead letter message`, { cause: err });
      throw err;
    }
  });
  return true;
};

export const retryDeadLetterMessage = async (context: AuthContext, user: AuthUser, deadLetterId: string) => {
  const deadLetterMessage = await findById(context, user, deadLetterId);
  if (!deadLetterMessage) {
    throw new Error(`Dead letter message with id ${deadLetterId} not found`);
  }
  const fileContent = await getFileContent(deadLetterMessage.file_id);
  if (!fileContent) {
    throw new Error(`Dead letter message with id ${deadLetterId} could not be loaded`);
  }
  await pushToConnector(CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, fileContent);
  return deleteDeadLetterMessage(context, user, deadLetterId);
};
