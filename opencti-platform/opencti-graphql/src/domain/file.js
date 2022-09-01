import { logApp } from '../config/conf';
import { loadFile, upload, uploadJobImport } from '../database/file-storage';

export const askJobImport = async (user, args) => {
  const { fileName, connectorId = null, bypassEntityId = null, bypassValidation = false } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(user, fileName);
  const entityId = bypassEntityId || file.metaData.entity_id;
  const opts = { manual: true, connectorId, bypassValidation };
  await uploadJobImport(user, file.id, file.metaData.mimetype, entityId, opts);
  return file;
};

export const uploadImport = async (user, file) => {
  return upload(user, 'import/global', file);
};

export const uploadPending = async (user, file, entityId = null) => {
  return upload(user, 'import/pending', file, entityId ? { entity_id: entityId } : {});
};
