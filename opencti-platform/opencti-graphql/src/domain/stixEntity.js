import { upload } from '../database/minio';

// eslint-disable-next-line
export const uploadFile = async ({ file, entityId }, user) =>
  upload(user, 'import', file, entityId);
