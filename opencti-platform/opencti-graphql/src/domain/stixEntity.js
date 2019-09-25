import { upload } from '../database/minio';

// eslint-disable-next-line
export const uploadFile = async ({ file, uploadType, entityId }) =>
  upload('import', file, uploadType, entityId);
