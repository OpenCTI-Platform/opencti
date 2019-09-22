import { upload } from '../database/minio';

// eslint-disable-next-line
export const uploadFile = async ({ file, uploadType, entityId, entityType }) =>
  upload(file, uploadType, entityType, entityId);
