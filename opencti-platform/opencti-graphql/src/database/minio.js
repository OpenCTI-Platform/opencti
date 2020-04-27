import * as Minio from 'minio';
import { assoc, concat, isEmpty, isNil, map, sort } from 'ramda';
import querystring from 'querystring';
import mime from 'mime-types';
import conf, { logger } from '../config/conf';
import { internalLoadEntityById, now, sinceNowInMinutes } from './grakn';
import { buildPagination } from './utils';
import { deleteWorkForFile, loadExportWorksAsProgressFiles } from '../domain/work';

const bucketName = conf.get('minio:bucket_name') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucket_region') || 'us-east-1';

const minioClient = new Minio.Client({
  endPoint: conf.get('minio:endpoint'),
  port: conf.get('minio:port') || 9000,
  useSSL: conf.get('minio:use_ssl') || false,
  accessKey: conf.get('minio:access_key'),
  secretKey: conf.get('minio:secret_key'),
});

export const isStorageAlive = () => {
  return new Promise((resolve, reject) => {
    minioClient.bucketExists(bucketName, (existErr, exists) => {
      if (existErr) reject(existErr);
      if (!exists) {
        minioClient.makeBucket(bucketName, bucketRegion, (createErr) => {
          if (createErr) reject(createErr);
          resolve(true);
        });
      }
      resolve(exists);
    });
  });
};

/**
 * Generate a filename for the export
 * @param format mime type like application/json*
 * @param connector the connector for the export
 * @param entity the target entity of the export (for entity)
 * @param type entity type to export (for list)
 * @param exportType the export type simple or full
 * @param maxMarkingDefinitionEntity the marking definition entity

 * @returns {string}
 */
export const generateFileExportName = (
  format,
  connector,
  entity = null,
  type = null,
  exportType = null,
  maxMarkingDefinitionEntity = null
) => {
  const creation = now();
  const fileExt = mime.extension(format);
  // entity and export type required when exporting a specific entity
  // type is required when exporting list
  const fileNamePart = entity && exportType ? `${entity.entity_type}-${entity.name}_${exportType}` : type;
  const maxMarking = maxMarkingDefinitionEntity ? `_${maxMarkingDefinitionEntity.definition}` : '';
  return `${creation}${maxMarking}_(${connector.name})_${fileNamePart}.${fileExt}`;
};

export const extractName = (entityType = null, entityId = null, filename = '') => {
  if (isEmpty(entityType) || isNil(entityType)) {
    return `global/${filename}`;
  }
  if (isEmpty(entityId) || isNil(entityId)) {
    return `${entityType.toLowerCase()}/lists/${filename}`;
  }
  return `${entityType.toLowerCase()}/${entityId}/${filename}`;
};

export const deleteFile = async (user, id) => {
  logger.debug(`FileManager > delete file ${id} by ${user.user_email}`);
  await minioClient.removeObject(bucketName, id);
  await deleteWorkForFile(id);
  return true;
};

export const downloadFile = (id) => minioClient.getObject(bucketName, id);

export const loadFile = async (filename) => {
  const stat = await minioClient.statObject(bucketName, filename);
  return {
    id: filename,
    name: querystring.unescape(stat.metaData.filename),
    size: stat.size,
    information: '',
    lastModified: stat.lastModified,
    lastModifiedSinceMin: sinceNowInMinutes(stat.lastModified),
    metaData: stat.metaData,
    uploadStatus: 'complete',
  };
};

const rawFilesListing = (directory) => {
  return new Promise((resolve, reject) => {
    const files = [];
    const stream = minioClient.listObjectsV2(bucketName, directory);
    stream.on('data', async (obj) => files.push(assoc('id', obj.name, obj)));
    /* istanbul ignore next */
    stream.on('error', (e) => {
      logger.error('MINIO > Error listing files', e);
      reject(e);
    });
    stream.on('end', () => resolve(files));
  }).then((files) => {
    return Promise.all(map((elem) => loadFile(elem.name), files));
  });
};

export const filesListing = async (first, category, entityType, entity = null, context = null) => {
  const name = extractName(entityType, entity ? entity.id : null);
  const files = await rawFilesListing(`${category}${context ? `/${context}` : ''}/${name}`);
  let allFiles = files;
  if (category === 'export') {
    const inExport = await loadExportWorksAsProgressFiles(entityType, entity ? entity.id : null, context);
    allFiles = concat(inExport, files);
  }
  const sortedFiles = sort((a, b) => b.lastModified - a.lastModified, allFiles);
  const fileNodes = map((f) => ({ node: f }), sortedFiles);
  return buildPagination(first, 0, fileNodes, allFiles.length);
};

export const upload = async (
  user,
  category,
  file,
  entityType = null,
  entityId = null,
  context = null,
  listArgs = null
) => {
  const { createReadStream, filename, mimetype, encoding } = await file;
  const metadata = {
    filename: querystring.escape(filename),
    category,
    mimetype,
    encoding,
    context,
    listArgs,
  };
  let finalEntityType = entityType;
  if (entityId && !finalEntityType) {
    const entity = await internalLoadEntityById(entityId);
    finalEntityType = entity.entity_type;
  }
  // eslint-disable-next-line prettier/prettier
  const fileDirName = `${category}${context ? `/${context}` : ''}/${extractName(finalEntityType, entityId, filename)}`;
  logger.debug(`FileManager > upload file ${filename} to ${fileDirName} by ${user.user_email}`);
  // Upload the file in the storage
  return new Promise((resolve, reject) => {
    return minioClient.putObject(bucketName, fileDirName, createReadStream(), null, metadata, (err) => {
      if (err) return reject(err);
      return resolve(loadFile(fileDirName));
    });
  });
};

export const getMinIOVersion = () => {
  const serverHeaderPrefix = 'MinIO/';
  return new Promise((resolve) => {
    // MinIO server information is included in the "Server" header of the
    // response. Make "bucketExists" request to get the header value.
    minioClient.makeRequest({ method: 'HEAD', bucketName }, '', 200, '', true, (err, response) => {
      /* istanbul ignore if */
      if (err) {
        logger.error('[MINIO] Error requesting server version: ', err);
        resolve('Disconnected');
        return;
      }
      const serverHeader = response.headers.server || '';
      /* istanbul ignore else */
      if (serverHeader.startsWith(serverHeaderPrefix)) {
        const version = serverHeader.substring(serverHeaderPrefix.length);
        resolve(version);
      } else {
        logger.error(`[MINIO] Unexpected Server header: '${serverHeader}'`);
        resolve('Unknown');
      }
    });
  });
};
