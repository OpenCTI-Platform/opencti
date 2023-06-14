import { logApp } from '../config/conf';
import { deleteFile, loadFile, upload, uploadJobImport } from '../database/file-storage';
import { internalLoadById } from '../database/middleware-loader';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';
import { stixCoreObjectImportDelete } from './stixCoreObject';

export const askJobImport = async (context, user, args) => {
  const { fileName, connectorId = null, bypassEntityId = null, bypassValidation = false } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(context, user, fileName);
  const entityId = bypassEntityId || file.metaData.entity_id;
  const opts = { manual: true, connectorId, bypassValidation };
  await uploadJobImport(context, user, file.id, file.metaData.mimetype, entityId, opts);
  return file;
};

export const uploadImport = async (context, user, file) => {
  const path = 'import/global';
  const up = await upload(context, user, path, file, {});
  const contextData = buildContextDataForFile(null, path, up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
};

export const uploadPending = async (context, user, file, entityId = null, labels = null, errorOnExisting = false) => {
  const meta = { labels_text: labels ? labels.join(';') : undefined };
  const entity = entityId ? await internalLoadById(context, user, entityId) : undefined;
  const up = await upload(context, user, 'import/pending', file, { meta, errorOnExisting, entity });
  const contextData = buildContextDataForFile(entity, 'import/pending', up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const deleteImport = async (context, user, fileName) => {
  // Imported file must be handled specifically
  // File deletion must publish a specific event
  // and update the updated_at field of the source entity
  if (fileName.startsWith('import') && !fileName.includes('global') && !fileName.includes('pending')) {
    await stixCoreObjectImportDelete(context, context.user, fileName);
    return true;
  }
  // If not, a simple deletion is enough
  const upDelete = await deleteFile(context, context.user, fileName);
  const contextData = buildContextDataForFile(null, fileName, upDelete.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'delete',
    context_data: contextData
  });
  return true;
};
