import * as Minio from 'minio';
import {
  assoc,
  filter,
  includes,
  isEmpty,
  concat,
  map,
  mergeDeepLeft
} from 'ramda';
import moment from 'moment';
import conf, { logger } from '../config/conf';
import { escapeString, find, getById } from './grakn';
import { buildPagination } from './utils';

export const SUFFIX_IMPORT = '.import.';
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

export const deleteFile = (id, user) => {
  logger.debug(`FileManager > delete file ${id} by ${user.email}`);
  return minioClient.removeObject(bucketName, id);
};

export const downloadFile = id => minioClient.getObject(bucketName, id);

const fileModifiedSinceMin = lastModified => {
  const now = moment().utc();
  const diff = now.diff(moment(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};

export const loadFile = async filename => {
  const stat = await minioClient.statObject(bucketName, filename);
  return {
    id: filename,
    name: stat.metaData.filename,
    size: stat.size,
    lastModified: stat.lastModified,
    lastModifiedSinceMin: fileModifiedSinceMin(stat.lastModified),
    metaData: stat.metaData,
    uploadStatus: 'complete'
  };
};

const rawFilesListing = directory => {
  return new Promise(resolve => {
    const files = [];
    const stream = minioClient.listObjectsV2(bucketName, directory, true);
    stream.on('data', async obj => files.push(assoc('id', obj.name, obj)));
    stream.on('end', () => resolve(files));
  }).then(files => Promise.all(map(elem => loadFile(elem.name), files)));
};

export const exportProgressFile = (id, name, lastModified) => {
  return {
    id,
    name,
    size: 0,
    lastModified,
    lastModifiedSinceMin: fileModifiedSinceMin(lastModified),
    uploadStatus: 'inProgress',
    metaData: {
      category: 'export'
    }
  };
};

export const exports = stixDomainEntityId => {
  const query = `match $e isa Export; $e has created_at $c; 
  (export: $e, exported: $x) isa exports; $x has internal_id "${escapeString(
    stixDomainEntityId
  )}"; get $e, $c; sort $c desc;`;
  return find(query, ['e']).then(exps =>
    map(i => exportProgressFile(i.e.id, i.e.name, i.e.updated_at), exps)
  );
};

export const filesListing = async (first, category, entity) => {
  const rawFiles = await rawFilesListing(
    `${category}/${extractName(entity.id, entity.entity_type)}`
  );
  const originalFiles = filter(e => !includes(SUFFIX_IMPORT, e.name), rawFiles);
  // For each file, find suffixed files to enrich the data
  const fileEnrich = file => {
    const extraFiles = filter(
      e => includes(e.name + SUFFIX_IMPORT, e.name),
      rawFiles
    );
    const extraConnectors = map(
      ex => ex.name.substring((ex.name + SUFFIX_IMPORT).length),
      extraFiles
    );
    return mergeDeepLeft(file, { connectors: extraConnectors });
  };
  const existingFiles = map(fileEnrich, originalFiles);
  let allFiles;
  if (category === 'export') {
    const inExport = await exports(entity.id);
    allFiles = concat(inExport, existingFiles);
  } else {
    allFiles = existingFiles;
  }
  const fileNodes = map(f => ({ node: f }), allFiles);
  return buildPagination(first, 0, fileNodes, allFiles.length);
};

// TODO Manage this Suffix: <file.extension>.import.<connector_name>
/*
export const fetchFileToImport = async (connectorName, directory) => {
  const suffix = `${SUFFIX_IMPORT}${connectorName}`;
  // The idea is to get a file available for processing.
  const filesFetching = await rawFilesListing(directory);
  // Filter files that are not in
  const filterFn = file => {
    const search = { name: `${file.name}${suffix}` };
    const isNoMarking = !includes(suffix, file.name);
    const isNotInImport = !includes(search, filesFetching);
    // If its not a marking and the list doesn't contains a marking for the file
    return isNoMarking && isNotInImport;
  };
  const availableFiles = filter(filterFn, filesFetching);
  // Try to
  return availableFiles;
};
*/

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
