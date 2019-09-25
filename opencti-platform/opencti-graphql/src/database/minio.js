import * as Minio from 'minio';
import { assoc, filter, includes, isEmpty, map, mergeDeepLeft } from 'ramda';
import conf from '../config/conf';
import { getById } from './grakn';

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

export const deleteFile = id => minioClient.removeObject(bucketName, id);

export const downloadFile = id => minioClient.getObject(bucketName, id);

export const loadFile = async filename => {
  const stat = await minioClient.statObject(bucketName, filename);
  return {
    id: filename,
    name: stat.metaData.filename,
    size: stat.size,
    lastModified: stat.lastModified,
    metaData: stat.metaData
  };
};

const rawFilesListing = directory => {
  return new Promise(resolve => {
    const files = [];
    const stream = minioClient.listObjectsV2(bucketName, directory, true);
    stream.on('data', async obj => files.push(assoc('id', obj.name, obj)));
    stream.on('end', () => resolve(files));
  }).then(files =>
    Promise.all(
      map(
        elem =>
          new Promise(resolve => {
            minioClient
              .statObject(bucketName, elem.name)
              .then(stat => {
                const namedFile = assoc('name', stat.metaData.filename, elem);
                return mergeDeepLeft(namedFile, stat);
              })
              .then(completeFile => resolve(completeFile));
          }),
        files
      )
    )
  );
};

export const filesListing = async (category, entityId) => {
  const entity = await getById(entityId);
  const rawFiles = await rawFilesListing(
    `${category}/${extractName(entityId, entity.entity_type)}`
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
  return map(fileEnrich, originalFiles);
};

// Suffix: <file.extension>.import.<connector_name>
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

export const upload = async (category, file, uploadType, entityId) => {
  const entity = await getById(entityId);
  const { createReadStream, filename, mimetype, encoding } = await file;
  const metadata = {
    filename,
    category,
    uploadtype: uploadType,
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
