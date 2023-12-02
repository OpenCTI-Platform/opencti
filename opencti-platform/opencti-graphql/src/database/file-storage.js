import * as s3 from '@aws-sdk/client-s3';
import * as R from 'ramda';
import { Upload } from '@aws-sdk/lib-storage';
import { Promise as BluePromise } from 'bluebird';
import { chain, CredentialsProviderError, memoize } from '@aws-sdk/property-provider';
import { remoteProvider } from '@aws-sdk/credential-provider-node/dist-cjs/remoteProvider';
import { defaultProvider } from '@aws-sdk/credential-provider-node/dist-cjs/defaultProvider';
import mime from 'mime-types';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import conf, { booleanConf, ENABLED_FILE_INDEX_MANAGER, logApp } from '../config/conf';
import { now, sinceNowInMinutes } from '../utils/format';
import { DatabaseError, FunctionalError } from '../config/errors';
import { createWork, deleteWorkForFile, deleteWorkForSource, loadExportWorksAsProgressFiles } from '../domain/work';
import { buildPagination, isEmptyField, isNotEmptyField } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';
import { telemetry } from '../config/tracing';
import { elDeleteFilesByIds } from './file-search';
import { isAttachmentProcessorEnabled } from './engine';
import { internalLoadById } from './middleware-loader';
import { SYSTEM_USER } from '../utils/access';
import { buildContextDataForFile, publishUserAction } from '../listener/UserActionListener';

// Minio configuration
const clientEndpoint = conf.get('minio:endpoint');
const clientPort = conf.get('minio:port') || 9000;
const clientAccessKey = conf.get('minio:access_key');
const clientSecretKey = conf.get('minio:secret_key');
const clientSessionToken = conf.get('minio:session_token');
const bucketName = conf.get('minio:bucket_name') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucket_region') || 'us-east-1';
const excludedFiles = conf.get('minio:excluded_files') || ['.DS_Store'];
const useSslConnection = booleanConf('minio:use_ssl', false);
const useAwsRole = booleanConf('minio:use_aws_role', false);
const isDefaultAwsProvider = booleanConf('minio:use_aws_default_provider', false);

const credentialProvider = (init) => memoize(
  chain(
    async () => {
      if (clientAccessKey && clientSecretKey && !useAwsRole) {
        return {
          accessKeyId: clientAccessKey,
          secretAccessKey: clientSecretKey,
          ...(clientSessionToken && { sessionToken: clientSessionToken })
        };
      }
      throw new CredentialsProviderError('Unable to load credentials from OpenCTI config');
    },
    isDefaultAwsProvider ? defaultProvider(init) : remoteProvider(init),
    async () => {
      throw new CredentialsProviderError('Could not load credentials from any providers', false);
    }
  ),
  (credentials) => credentials.expiration !== undefined && credentials.expiration.getTime() - Date.now() < 300000,
  (credentials) => credentials.expiration !== undefined
);

const getEndpoint = () => {
  // If using AWS S3, unset the endpoint to let the library choose the best endpoint
  if (clientEndpoint === 's3.amazonaws.com') {
    return undefined;
  }
  return `${(useSslConnection ? 'https' : 'http')}://${clientEndpoint}:${clientPort}`;
};

const s3Client = new s3.S3Client({
  region: bucketRegion,
  endpoint: getEndpoint(),
  forcePathStyle: true,
  credentialDefaultProvider: credentialProvider,
  tls: useSslConnection
});

export const initializeBucket = async () => {
  try {
    // Try to access to the bucket
    await s3Client.send(new s3.HeadBucketCommand({ Bucket: bucketName }));
    return true;
  } catch (err) {
    // If bucket not exist, try to create it.
    // If creation fail, propagate the exception
    await s3Client.send(new s3.CreateBucketCommand({ Bucket: bucketName }));
    return true;
  }
};

export const deleteBucket = async () => {
  try {
    // Try to access to the bucket
    await s3Client.send(new s3.DeleteBucketCommand({ Bucket: bucketName }));
  } catch (err) {
    // Dont care
  }
};

export const isStorageAlive = () => initializeBucket();

export const deleteFile = async (context, user, id) => {
  const up = await loadFile(user, id);
  logApp.debug(`[FILE STORAGE] delete file ${id} by ${user.user_email}`);
  await s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  await deleteWorkForFile(context, user, id);
  // delete in index if file has been indexed
  // TODO test if file index manager is activated (dependency cycle issue with isModuleActivated)
  if (ENABLED_FILE_INDEX_MANAGER && isAttachmentProcessorEnabled()) {
    logApp.info(`[FILE STORAGE] delete file ${id} in index`);
    await elDeleteFilesByIds([id])
      .catch((databaseError) => {
        logApp.error('[FILE STORAGE] Error deleting file in index', { databaseError });
      });
  }
  return up;
};

export const deleteFiles = async (context, user, ids) => {
  logApp.debug(`[FILE STORAGE] delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    await deleteFile(context, user, id);
  }
  return true;
};

export const downloadFile = async (id) => {
  try {
    const object = await s3Client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: id
    }));
    return object.Body;
  } catch (err) {
    logApp.info('[OPENCTI] Cannot retrieve file from S3', { error: err });
    return null;
  }
};

export const streamToString = (stream, encoding = 'utf8') => {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString(encoding)));
  });
};

export const getFileContent = async (id, encoding = 'utf8') => {
  const object = await s3Client.send(new s3.GetObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  return streamToString(object.Body, encoding);
};

export const storeFileConverter = (user, file) => {
  return {
    id: file.id,
    name: file.name,
    version: file.metaData.version,
    mime_type: file.metaData.mimetype,
  };
};

export const loadFile = async (user, filename) => {
  try {
    const object = await s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: filename
    }));
    const metaData = {
      ...object.Metadata,
      mimetype: object.Metadata.mimetype,
      entity_id: object.Metadata.entity_id,
      messages: [],
      errors: [],
    };
    if (metaData.labels_text) {
      metaData.labels = metaData.labels_text.split(';');
    }
    return {
      id: filename,
      name: decodeURIComponent(object.Metadata.filename || 'unknown'),
      size: object.ContentLength,
      information: '',
      lastModified: object.LastModified,
      lastModifiedSinceMin: sinceNowInMinutes(object.LastModified),
      metaData,
      uploadStatus: 'complete'
    };
  } catch (err) {
    if (err instanceof s3.NoSuchKey) {
      throw DatabaseError('File not found', { user_id: user.id, filename });
    }
    throw err;
  }
};
const getFileName = (fileId) => {
  return fileId?.includes('/') ? R.last(fileId.split('/')) : fileId;
};
const guessMimeType = (fileId) => {
  const fileName = getFileName(fileId);
  const mimeType = mime.lookup(fileName) || null;
  if (!mimeType && fileName === 'pdf_report') {
    return 'application/pdf';
  }
  return mimeType;
};

export const checkFileAccess = async (context, user, scope, loadedFile) => {
  const { entity_id, filename } = loadedFile.metaData;
  if (isEmptyField(entity_id)) {
    return true;
  }
  const userInstancePromise = internalLoadById(context, user, entity_id);
  const systemInstancePromise = internalLoadById(context, SYSTEM_USER, entity_id);
  const [instance, systemInstance] = await Promise.all([userInstancePromise, systemInstancePromise]);
  if (isEmptyField(instance)) {
    if (isNotEmptyField(systemInstance)) {
      const data = buildContextDataForFile(systemInstance, loadedFile.id, filename);
      await publishUserAction({
        user,
        event_type: 'file',
        event_scope: scope,
        event_access: 'extended',
        status: 'error',
        context_data: data
      });
    }
    throw FunctionalError('FILE_ACCESS', { id: entity_id, file: loadedFile.id });
  }
  return true;
};

export const isFileObjectExcluded = (id) => {
  const fileName = getFileName(id);
  return excludedFiles.map((e) => e.toLowerCase()).includes(fileName.toLowerCase());
};

const simpleFilesListing = async (directory, opts = {}) => {
  const { recursive = false } = opts;
  const { modifiedSince, maxFileSize, mimeTypes = [], excludedPaths = [], includedPaths = [] } = opts;
  const objects = [];
  const requestParams = {
    Bucket: bucketName,
    Prefix: directory || undefined,
    Delimiter: recursive ? undefined : '/'
  };
  let truncated = true;
  while (truncated) {
    try {
      const response = await s3Client.send(new s3.ListObjectsV2Command(requestParams));
      objects.push(...(response.Contents ?? []));
      truncated = response.IsTruncated;
      if (truncated) {
        requestParams.ContinuationToken = response.NextContinuationToken;
      }
    } catch (err) {
      logApp.error('[FILE STORAGE] Error loading files list', { error: err });
      truncated = false;
    }
  }
  const storageObjects = objects.map((obj) => {
    return {
      ...obj,
      mimeType: guessMimeType(obj.Key),
    };
  });
  const filteredObjects = storageObjects.filter((obj) => {
    return !isFileObjectExcluded(obj.Key)
      && (!mimeTypes?.length || mimeTypes.includes(obj.mimeType))
      && (!modifiedSince || obj.LastModified > modifiedSince)
      && (!maxFileSize || maxFileSize >= obj.Size)
      && (!includedPaths?.length || includedPaths.some((includedPath) => obj.Key.startsWith(includedPath)))
      && (!excludedPaths?.length || !excludedPaths.some((excludedPath) => obj.Key.startsWith(excludedPath)));
  });
  return filteredObjects;
};

export const rawFilesListing = async (context, user, directory, opts = {}) => {
  const storageObjects = await simpleFilesListing(directory, opts);
  // Load file metadata with 5 // call maximum
  return BluePromise.map(storageObjects, (f) => loadFile(user, f.Key), { concurrency: 5 });
};

export const uploadJobImport = async (context, user, fileId, fileMime, entityId, opts = {}) => {
  const { manual = false, connectorId = null, configuration = null, bypassValidation = false } = opts;
  let connectors = await connectorsForImport(context, user, fileMime, true, !manual);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (!entityId) {
    connectors = R.filter((n) => !n.only_contextual, connectors);
  }
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector) => {
      const work = await createWork(context, user, connector, 'Manual import', fileId);
      return { connector, work };
    };
    const actionList = await Promise.all(connectors.map((connector) => createConnectorWork(connector)));
    // Send message to all correct connectors queues
    const buildConnectorMessage = (data, connectorConfiguration) => {
      const { work } = data;
      return {
        internal: {
          work_id: work.id, // Related action for history
          applicant_id: user.id, // User asking for the import
        },
        event: {
          file_id: fileId,
          file_mime: fileMime,
          file_fetch: `/storage/get/${fileId}`, // Path to get the file
          entity_id: entityId, // Context of the upload
          bypass_validation: bypassValidation, // Force no validation
        },
        configuration: connectorConfiguration
      };
    };
    const pushMessage = (data) => {
      const { connector } = data;
      const message = buildConnectorMessage(data, configuration);
      return pushToConnector(connector.internal_id, message);
    };
    await Promise.all(actionList.map((data) => pushMessage(data)));
  }
  return connectors;
};

export const upload = async (context, user, path, fileUpload, opts) => {
  const { entity, meta = {}, noTriggerImport = false, errorOnExisting = false } = opts;
  const { createReadStream, filename, mimetype, encoding = '' } = await fileUpload;
  const key = `${path}/${filename}`;
  let existingFile = null;
  try {
    existingFile = await loadFile(user, key);
  } catch {
    // do nothing
  }
  if (errorOnExisting && existingFile) {
    throw FunctionalError('A file already exists with this name');
  }
  // Upload the data
  const readStream = createReadStream();
  const fileMime = mime.lookup(filename) || mimetype;
  const metadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  const fullMetadata = {
    ...metadata,
    filename: encodeURIComponent(filename),
    mimetype: fileMime,
    encoding,
    creator_id: user.id,
    entity_id: entity?.internal_id,
  };
  const s3Upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: key,
      Body: readStream,
      Metadata: fullMetadata
    }
  });
  await s3Upload.done();
  const file = {
    id: key,
    name: filename,
    size: readStream.bytesRead,
    information: '',
    lastModified: new Date(),
    lastModifiedSinceMin: sinceNowInMinutes(new Date()),
    metaData: { ...fullMetadata, messages: [], errors: [] },
    uploadStatus: 'complete'
  };
  // Trigger a enrich job for import file if needed
  if (!noTriggerImport && path.startsWith('import/') && !path.startsWith('import/pending') && !path.startsWith('import/External-Reference')) {
    await uploadJobImport(context, user, file.id, file.metaData.mimetype, file.metaData.entity_id);
  }
  return file;
};

export const filesListing = async (context, user, first, path, entity = null, prefixMimeType = '') => {
  const filesListingFn = async () => {
    let files = await rawFilesListing(context, user, path);
    if (entity) {
      files = files.filter((file) => file.metaData.entity_id === entity.internal_id);
      files = await resolveImageFiles(files, entity);
    }
    if (prefixMimeType) {
      files = files.filter((file) => file.metaData.mimetype.includes(prefixMimeType));
    }
    const inExport = await loadExportWorksAsProgressFiles(context, user, path);
    const allFiles = R.concat(inExport, files);
    const sortedFiles = allFiles.sort((a, b) => b.lastModified - a.lastModified);
    const fileNodes = sortedFiles.map((f) => ({ node: f }));
    return buildPagination(first, null, fileNodes, fileNodes.length);
  };
  return telemetry(context, user, `STORAGE ${path}`, {
    [SemanticAttributes.DB_NAME]: 'storage_engine',
    [SemanticAttributes.DB_OPERATION]: 'listing',
  }, filesListingFn);
};

export const fileListingForIndexing = async (context, user, path, opts = {}) => {
  const fileListingForIndexingFn = async () => {
    const files = await simpleFilesListing(path, { ...opts, recursive: true });
    return files.sort((a, b) => a.LastModified - b.LastModified);
  };
  return telemetry(context, user, `STORAGE ${path}`, {
    [SemanticAttributes.DB_NAME]: 'storage_engine',
    [SemanticAttributes.DB_OPERATION]: 'listing',
  }, fileListingForIndexingFn);
};

export const loadFilesForIndexing = (user, files, opts = {}) => {
  let filesObjects = BluePromise.map(files, (f) => loadFile(user, f.Key), { concurrency: 5 });
  const { mimeTypes } = opts;
  if (mimeTypes?.length > 0) {
    filesObjects = filesObjects.filter((file) => {
      return file.metaData?.mimetype && mimeTypes.includes(file.metaData.mimetype);
    });
  }
  return filesObjects;
};

export const deleteAllObjectFiles = async (context, user, element) => {
  const importPath = `import/${element.entity_type}/${element.internal_id}/`;
  const importFilesPromise = simpleFilesListing(importPath);
  const importWorkPromise = deleteWorkForSource(importPath);
  const exportPath = `export/${element.entity_type}/${element.internal_id}/`;
  const exportFilesPromise = simpleFilesListing(exportPath);
  const exportWorkPromise = deleteWorkForSource(exportPath);
  const [importFiles, exportFiles, _, __] = await Promise.all([
    importFilesPromise,
    exportFilesPromise,
    importWorkPromise,
    exportWorkPromise
  ]);
  const ids = [...importFiles, ...exportFiles].map((file) => file.Key);
  return deleteFiles(context, user, ids);
};

const resolveImageFiles = async (files, resolveEntity) => {
  const elasticFiles = resolveEntity.x_opencti_files;
  return files.map((file) => {
    const elasticFile = (elasticFiles ?? []).find((e) => e.id === file.id);
    if (elasticFile) {
      return {
        ...file,
        metaData: {
          ...file.metaData,
          order: elasticFile.order,
          inCarousel: elasticFile.inCarousel,
          description: elasticFile.description
        }
      };
    }
    return file;
  }).sort((a, b) => {
    const orderA = a.metaData?.order ?? Infinity;
    const orderB = b.metaData?.order ?? Infinity;
    return orderA - orderB;
  });
};
