import * as Minio from 'minio';
import { assoc, isEmpty, concat, map } from 'ramda';
import mime from 'mime-types';
import conf, { logger } from '../config/conf';
import { getById, now, sinceNowInMinutes } from './grakn';
import { buildPagination } from './utils';
import { loadExportWorksAsProgressFiles } from '../domain/work';

const bucketName = conf.get('minio:bucketName') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucketRegion') || 'us-east-1';

const minioClient = new Minio.Client({
  endPoint: conf.get('minio:endpoint'),
  port: conf.get('minio:port') || 9000,
  useSSL: conf.get('minio:useSSL') || false,
  accessKey: conf.get('minio:accessKey'),
  secretKey: conf.get('minio:secretKey')
});

export const isStorageAlive = () => {
  return new Promise((resolve, reject) => {
    minioClient.bucketExists(bucketName, (existErr, exists) => {
      if (existErr) reject(existErr);
      if (!exists) {
        minioClient.makeBucket(bucketName, bucketRegion, createErr => {
          if (createErr) reject(createErr);
          resolve(true);
        });
      }
      resolve(exists);
    });
  });
};

const extractName = (entityId, entityType, filename = '') => {
  return isEmpty(entityType)
    ? filename
    : `${entityType}/${entityId}/${filename}`;
};

/**
 * Generate a filename for the export
 * @param format mime type like application/json
 * @param connector the connector for the export
 * @param exportType the export type simple or full
 * @param entity the target entity of the export
 * @returns {string}
 */
export const generateFileExportName = (
  format,
  connector,
  exportType,
  entity
) => {
  const creation = now();
  const fileExt = mime.extension(format);
  const entityInFile = entity
    ? `${entity.entity_type}-${entity.name}`
    : `global`;
  return `${creation}_(${connector.name})_${entityInFile}_${exportType}.${fileExt}`;
};

export const deleteFile = (id, user) => {
  logger.debug(`FileManager > delete file ${id} by ${user.email}`);
  return minioClient.removeObject(bucketName, id);
};

export const downloadFile = id => minioClient.getObject(bucketName, id);

export const loadFile = async filename => {
  const stat = await minioClient.statObject(bucketName, filename);
  return {
    id: filename,
    name: stat.metaData.filename,
    size: stat.size,
    information: '',
    lastModified: stat.lastModified,
    lastModifiedSinceMin: sinceNowInMinutes(stat.lastModified),
    metaData: stat.metaData,
    uploadStatus: 'complete'
  };
};

const rawFilesListing = directory => {
  return new Promise(resolve => {
    const files = [];
    const stream = minioClient.listObjectsV2(bucketName, directory, true);
    stream.on('data', async obj => files.push(assoc('id', obj.name, obj)));
    stream.on('error', e => logger.error('MINIO > Error listing files', e));
    stream.on('end', () => resolve(files));
  }).then(files => Promise.all(map(elem => loadFile(elem.name), files)));
};

export const filesListing = async (first, category, entity) => {
  const name = `${extractName(entity.id, entity.entity_type)}`;
  const files = await rawFilesListing(`${category}/${name}`);
  let allFiles = files;
  if (category === 'export') {
    const inExport = await loadExportWorksAsProgressFiles(entity.id);
    allFiles = concat(inExport, files);
  }
  const fileNodes = map(f => ({ node: f }), allFiles);
  return buildPagination(first, 0, fileNodes, allFiles.length);
};

export const upload = async (user, category, file, entityId) => {
  const entity = await getById(entityId);
  const { createReadStream, filename, mimetype, encoding } = await file;
  logger.debug(`FileManager > upload file ${filename} by ${user.email}`);
  // Minio does not support UpperCase un metadata
  // noinspection SpellCheckingInspection
  const metadata = {
    filename,
    category,
    mimetype,
    encoding,
    entitytype: entity.entity_type,
    entityid: entityId
  };
  const fileDirName = `${category}/${extractName(
    entityId,
    entity.entity_type,
    filename
  )}`;
  // Upload the file in the storage
  return new Promise((resolve, reject) => {
    minioClient.putObject(
      bucketName,
      fileDirName,
      createReadStream(),
      null,
      metadata,
      err => {
        if (err) reject(err);
        resolve(loadFile(fileDirName));
      }
    );
  });
};
