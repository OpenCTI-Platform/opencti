import { upload } from '../database/minio';

// eslint-disable-next-line
export const uploadFile = async ({ file, uploadType, entityId }, user) =>
  upload(user, 'import', file, uploadType, entityId);
