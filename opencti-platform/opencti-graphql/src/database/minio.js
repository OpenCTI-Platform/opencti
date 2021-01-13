import * as Minio from 'minio';
import { assoc, concat, map, sort } from 'ramda';
import querystring from 'querystring';
import conf, { logger } from '../config/conf';
import { sinceNowInMinutes } from './middleware';
import { buildPagination } from './utils';
import { loadExportWorksAsProgressFiles, deleteWork } from '../domain/work';

const bucketName = conf.get('minio:bucket_name') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucket_region') || 'us-east-1';

const minioClient = new Minio.Client({
  endPoint: conf.get('minio:endpoint'),
  port: conf.get('minio:port') || 9000,
  useSSL: conf.get('minio:use_ssl') || false,
  accessKey: String(conf.get('minio:access_key')),
  secretKey: String(conf.get('minio:secret_key')),
});

export const isStorageAlive = () => {
  return new Promise((resolve, reject) => {
    try {
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
    } catch (e) {
      reject(e);
    }
  });
};

export const deleteFile = async (user, id) => {
  logger.debug(`[MINIO] delete file ${id} by ${user.user_email}`);
  await minioClient.removeObject(bucketName, id);
  await deleteWork(id);
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
    metaData: { ...stat.metaData, messages: [], errors: [] },
    uploadStatus: 'complete',
  };
};

const rawFilesListing = (directory) => {
  return new Promise((resolve, reject) => {
    const files = [];
    const stream = minioClient.listObjectsV2(bucketName, directory);
    stream.on('data', async (obj) => {
      if (obj.size > 0) {
        files.push(assoc('id', obj.name, obj));
      }
    });
    /* istanbul ignore next */
    stream.on('error', (e) => {
      logger.error('[MINIO] Error listing files', { error: e });
      reject(e);
    });
    stream.on('end', () => resolve(files));
  }).then((files) => {
    return Promise.all(map((elem) => loadFile(elem.name), files));
  });
};

export const upload = async (user, path, file, metadata = {}) => {
  const { createReadStream, filename, mimetype, encoding } = await file;
  const escapeName = querystring.escape(filename);
  const internalMeta = { filename: escapeName, mimetype, encoding };
  const fileMeta = { ...metadata, ...internalMeta };
  const fileDirName = `${path}/${filename}`;
  logger.debug(`[MINIO] Upload file ${fileDirName} by ${user.user_email}`);
  // Upload the file in the storage
  return new Promise((resolve, reject) => {
    return minioClient.putObject(bucketName, fileDirName, createReadStream(), null, fileMeta, (err) => {
      if (err) return reject(err);
      return resolve(loadFile(fileDirName));
    });
  });
};

export const filesListing = async (first, path) => {
  const files = await rawFilesListing(path);
  const inExport = await loadExportWorksAsProgressFiles(path);
  const allFiles = concat(inExport, files);
  const sortedFiles = sort((a, b) => b.lastModified - a.lastModified, allFiles);
  const fileNodes = map((f) => ({ node: f }), sortedFiles);
  return buildPagination(first, 0, fileNodes, allFiles.length);
};

export const getMinIOVersion = () => {
  const serverHeaderPrefix = 'MinIO/';
  return new Promise((resolve) => {
    // MinIO server information is included in the "Server" header of the
    // response. Make "bucketExists" request to get the header value.
    minioClient.makeRequest({ method: 'HEAD', bucketName }, '', 200, '', true, (err, response) => {
      /* istanbul ignore if */
      if (err) {
        logger.error('[MINIO] Error requesting server version: ', { error: err });
        resolve('Disconnected');
        return;
      }
      const serverHeader = response.headers.server || '';
      /* istanbul ignore else */
      if (serverHeader.startsWith(serverHeaderPrefix)) {
        const version = serverHeader.substring(serverHeaderPrefix.length);
        resolve(version);
      } else {
        // logger.error(`[MINIO] Unexpected Server header`, { headers: serverHeader });
        resolve('Latest');
      }
    });
  });
};
