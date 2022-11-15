import { logApp } from '../config/conf';
import { loadFile, upload, uploadJobImport } from '../database/file-storage';

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
  return upload(context, user, 'import/global', file);
};

export const uploadPending = async (context, user, file, entityId = null, labels = null, errorOnExisting = false) => {
  const meta = {};
  if (entityId) { meta.entity_id = entityId; }
  if (labels) { meta.labels_text = labels.join(';'); }
  return upload(context, user, 'import/pending', file, meta, false, errorOnExisting);
};
