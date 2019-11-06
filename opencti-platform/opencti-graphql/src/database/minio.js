import * as Minio from 'minio';
import { assoc, isEmpty, concat, map, isNil, sort } from 'ramda';
import querystring from 'querystring';
import mime from 'mime-types';
import conf, { logger } from '../config/conf';
import { loadEntityById, now, sinceNowInMinutes } from './grakn';
import { buildPagination } from './utils';
import {
  deleteWorkForFile,
  loadExportWorksAsProgressFiles
} from '../domain/work';

const bucketName = conf.get('minio:bucket_name') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucket_region') || 'us-east-1';

const minioClient = new Minio.Client({
  endPoint: conf.get('minio:endpoint'),
  port: conf.get('minio:port') || 9000,
  useSSL: conf.get('minio:use_ssl') || false,
  accessKey: conf.get('minio:access_key'),
  secretKey: conf.get('minio:secret_key')
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
  return isEmpty(entityType) || isNil(entityType)
    ? `global/${filename}`
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
  const entityInFile = `${entity.entity_type}-${entity.name}`;
  return `${creation}_(${connector.name})_${entityInFile}_${exportType}.${fileExt}`;
};

export const deleteFile = async (id, user) => {
  logger.debug(`FileManager > delete file ${id} by ${user.email}`);
  await minioClient.removeObject(bucketName, id);
  await deleteWorkForFile(id);
  return true;
};

export const downloadFile = id => minioClient.getObject(bucketName, id);

export const loadFile = async filename => {
  const stat = await minioClient.statObject(bucketName, filename);
  return {
    id: filename,
    name: querystring.unescape(stat.metaData.filename),
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
    const stream = minioClient.listObjectsV2(bucketName, directory);
    stream.on('data', async obj => files.push(assoc('id', obj.name, obj)));
    stream.on('error', e => logger.error('MINIO > Error listing files', e));
    stream.on('end', () => resolve(files));
  }).then(files => {
    return Promise.all(map(elem => loadFile(elem.name), files));
  });
};

export const filesListing = async (first, category, entity = null) => {
  const name = extractName(
    entity ? entity.id : null,
    entity ? entity.entity_type : null
  );
  const files = await rawFilesListing(`${category}/${name}`);
  let allFiles = files;
  if (category === 'export') {
    const inExport = await loadExportWorksAsProgressFiles(entity.id);
    allFiles = concat(inExport, files);
  }
  const sortedFiles = sort((a, b) => b.lastModified - a.lastModified, allFiles);
  const fileNodes = map(f => ({ node: f }), sortedFiles);
  return buildPagination(first, 0, fileNodes, allFiles.length);
};

export const upload = async (user, category, file, entityId = null) => {
  const { createReadStream, filename, mimetype, encoding } = await file;
  const metadata = {
    filename: querystring.escape(filename),
    category,
    mimetype,
    encoding
  };
  let entityType = null;
  if (entityId) {
    const entity = await loadEntityById(entityId);
    entityType = entity.entity_type;
  }
  const fileDirName = `${category}/${extractName(
    entityId,
    entityType,
    filename
  )}`;
  logger.debug(`FileManager > upload file ${filename} by ${user.email}`);
  // Upload the file in the storage
  return new Promise((resolve, reject) => {
    return minioClient.putObject(
      bucketName,
      fileDirName,
      createReadStream(),
      null,
      metadata,
      err => {
        if (err) return reject(err);
        return resolve(loadFile(fileDirName));
      }
    );
  });
};
