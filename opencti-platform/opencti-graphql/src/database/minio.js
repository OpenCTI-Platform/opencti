import * as Minio from 'minio';
import conf, { logger } from '../config/conf';

const { Readable } = require('stream');

const bucketName = conf.get('minio:bucketName') || 'OPENCTI_BUCKET';
const bucketRegion = conf.get('minio:bucketRegion') || 'us-east-1';

const minioClient = new Minio.Client({
  endPoint: conf.get('minio:endpoint'),
  port: conf.get('minio:port') || 9000,
  useSSL: conf.get('minio:useSSL') || true,
  accessKey: conf.get('minio:accessKey'),
  secretKey: conf.get('minio:secretKey')
});

export const isStorageAlive = () => {
  return new Promise((resolve, reject) => {
    minioClient.bucketExists(bucketName, (existErr, exists) => {
      if (existErr) reject(existErr);
      if (exists) {
        minioClient.makeBucket(bucketName, bucketRegion, createErr => {
          if (createErr) reject(createErr);
          resolve(true);
        });
      }
      resolve(exists);
    });
  });
};

export const uploadExport = async (fileName, data) => {
  const fileStream = new Readable();
  fileStream.push(data); // the string you want
  fileStream.push(null);
  // Upload the file in the storage
  const upload = await new Promise((resolve, reject) => {
    minioClient.putObject(
      bucketName,
      fileName,
      fileStream,
      null,
      (err, etag) => {
        if (err) reject(err);
        return etag;
      }
    );
  });
  // Update grakn with the access reference
  // TODO
};
