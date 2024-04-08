import * as s3 from '@aws-sdk/client-s3';
import * as R from 'ramda';
import path from 'node:path';
import { Upload } from '@aws-sdk/lib-storage';
import { Promise as BluePromise } from 'bluebird';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import mime from 'mime-types';
import { CopyObjectCommand } from '@aws-sdk/client-s3';
import conf, { booleanConf, ENABLED_FILE_INDEX_MANAGER, logApp, logS3Debug } from '../config/conf';
import { now, sinceNowInMinutes, truncate, utcDate } from '../utils/format';
import { DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import { createWork, deleteWorkForFile } from '../domain/work';
import { isNotEmptyField } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';
import { elDeleteFilesByIds } from './file-search';
import { isAttachmentProcessorEnabled } from './engine';
import { deleteDocumentIndex, findById as documentFindById, indexFileToDocument } from '../modules/internal/document/document-domain';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { enrichWithRemoteCredentials } from '../config/credentials';

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
const useAwsLogs = booleanConf('minio:use_aws_logs', false);

let s3Client; // Client reference

export const specialTypesExtensions = {
  'application/vnd.oasis.stix+json': 'json',
  'application/vnd.mitre.navigator+json': 'json',
};

const buildCredentialProvider = async () => {
  // If aws role must be used
  if (useAwsRole) {
    return () => {
      return defaultProvider({
        roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity({
          // You must explicitly pass a region if you are not using us-east-1
          region: bucketRegion
        })
      });
    };
  }
  // If direct configuration
  const baseAuth = { accessKeyId: clientAccessKey, secretAccessKey: clientSecretKey };
  const userPasswordAuth = await enrichWithRemoteCredentials('minio', baseAuth);
  return () => {
    return {
      ...userPasswordAuth,
      ...(clientSessionToken && { sessionToken: clientSessionToken })
    };
  };
};

const getEndpoint = () => {
  // If using AWS S3, unset the endpoint to let the library choose the best endpoint
  if (clientEndpoint === 's3.amazonaws.com') {
    return undefined;
  }
  return `${(useSslConnection ? 'https' : 'http')}://${clientEndpoint}:${clientPort}`;
};

export const initializeFileStorageClient = async () => {
  s3Client = new s3.S3Client({
    region: bucketRegion,
    endpoint: getEndpoint(),
    forcePathStyle: true,
    credentialDefaultProvider: await buildCredentialProvider(),
    logger: useAwsLogs ? logS3Debug : undefined,
    tls: useSslConnection
  });
};

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
    logApp.info('[FILE STORAGE] Bucket cannot be deleted.', { err });
  }
};

export const storageInit = async () => {
  await initializeFileStorageClient();
  await initializeBucket();
};

export const isStorageAlive = () => initializeBucket();

export const deleteFile = async (context, user, id) => {
  const up = await loadFile(context, user, id);
  logApp.debug(`[FILE STORAGE] delete file ${id} by ${user.user_email}`);
  // Delete in S3
  await s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  // Delete associated works
  await deleteWorkForFile(context, user, id);
  // Delete index file
  await deleteDocumentIndex(context, user, id);
  // delete in index if file has been indexed
  // TODO test if file index manager is activated (dependency cycle issue with isModuleActivated)
  if (ENABLED_FILE_INDEX_MANAGER && isAttachmentProcessorEnabled()) {
    logApp.debug(`[FILE STORAGE] delete file ${id} in index`);
    await elDeleteFilesByIds([id])
      .catch((err) => {
        logApp.error(err);
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

/**
 * Download a file from S3 at given S3 key (id)
 * @param id
 * @returns {Promise<*|null>} null when error occurs on download.
 */
export const downloadFile = async (id) => {
  try {
    const object = await s3Client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: id
    }));
    if (!object || !object.Body) {
      logApp.error('[FILE STORAGE] Cannot retrieve file from S3, null body in response', { fileId: id });
      return null;
    }
    return object.Body;
  } catch (err) {
    logApp.error('[FILE STORAGE] Cannot retrieve file from S3', { error: err, fileId: id });
    return null;
  }
};

/**
 * - Copy file from a place to another in S3
 * - Store file in documents
 * @param sourceId
 * @param targetId
 * @param sourceDocument
 * @param targetEntityId
 * @returns {Promise<null|void>} the document entity on success, null on errors.
 */
export const copyFile = async (sourceId, targetId, sourceDocument, targetEntityId) => {
  try {
    const input = {
      Bucket: bucketName,
      CopySource: `${bucketName}/${sourceId}`, // CopySource must start with bucket name, but not Key
      Key: targetId
    };
    const command = new CopyObjectCommand(input);
    await s3Client.send(command);
    // Register in elastic
    const targetMetadata = { ...sourceDocument.metaData, entity_id: targetEntityId };

    const file = {
      id: targetId,
      name: sourceDocument.name,
      size: sourceDocument.size,
      information: '',
      lastModified: new Date(),
      lastModifiedSinceMin: sinceNowInMinutes(new Date()),
      metaData: targetMetadata,
      uploadStatus: 'complete',
    };
    await indexFileToDocument(file);
    logApp.info('[FILE STORAGE] Copy file to S3 in success', { document: file, sourceId, targetId });
    return file;
  } catch (err) {
    logApp.error('[FILE STORAGE] Cannot copy file in S3', { error: err, sourceId, targetId });
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

/**
 * Convert File object coming from uploadToStorage/upload functions to x_opencti_file format.
 */
export const storeFileConverter = (user, file) => {
  return {
    id: file.id,
    name: file.name,
    version: file.metaData.version,
    mime_type: file.metaData.mimetype,
  };
};

/**
 * Get file size from S3 (calling HEAD on S3 file).
 */
export const getFileSize = async (user, fileS3Path) => {
  try {
    const object = await s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: fileS3Path
    }));
    return object.ContentLength;
  } catch (err) {
    throw UnsupportedError('Load file from storage fail', { cause: err, user_id: user.id, filename: fileS3Path });
  }
};

/**
 * Get file metadata from database, or else from S3.
 */
export const loadFile = async (context, user, fileS3Path, opts = {}) => {
  const fileInformationFromDB = await documentFindById(context, user, fileS3Path);
  const { dontThrow = false } = opts;
  try {
    let metaData; let name; let size; let lastModified; let lastModifiedSinceMin;

    // Try first to get metadata from elastic
    if (fileInformationFromDB) {
      metaData = fileInformationFromDB.metaData;
      name = fileInformationFromDB.name;
      size = fileInformationFromDB.size;
      lastModified = fileInformationFromDB.lastModified;
      lastModifiedSinceMin = fileInformationFromDB.lastModifiedSinceMin;
    } else {
      // Else try to get them from S3 instead
      const object = await s3Client.send(new s3.HeadObjectCommand({
        Bucket: bucketName,
        Key: fileS3Path
      }));
      size = object.ContentLength;
      lastModified = object.LastModified;
      lastModifiedSinceMin = sinceNowInMinutes(object.LastModified);

      if (object.Metadata) {
        metaData = {
          version: object.Metadata.version,
          description: object.Metadata.description,
          list_filters: object.Metadata.list_filters,
          filename: object.Metadata.filename,
          mimetype: object.Metadata.mimetype,
          labels_text: object.Metadata.labels_text,
          labels: object.Metadata.labels_text ? object.Metadata.labels_text.split(';') : [],
          encoding: object.Metadata.encoding,
          creator_id: object.Metadata.creator_id,
          entity_id: object.Metadata.entity_id,
          external_reference_id: object.Metadata.external_reference_id,
          messages: object.Metadata.messages,
          errors: object.Metadata.errors,
          inCarousel: object.Metadata.inCarousel,
          order: object.Metadata.order
        };
        name = decodeURIComponent(object.Metadata.filename || 'unknown');
      } else {
        const mimeTypeResolved = guessMimeType(fileS3Path);
        metaData = { mimetype: mimeTypeResolved };
        name = getFileName(fileS3Path);
      }
    }

    return {
      id: fileS3Path,
      name,
      size,
      information: '',
      lastModified,
      lastModifiedSinceMin,
      uploadStatus: 'complete',
      metaData
    };
  } catch (err) {
    if (dontThrow) {
      logApp.error('[FILE STORAGE] Load file from storage fail', { cause: err, user_id: user.id, filename: fileS3Path });
      return undefined;
    }
    throw UnsupportedError('Load file from storage fail', { cause: err, user_id: user.id, filename: fileS3Path });
  }
};

/**
 * Get (filename + extension) from S3 file full path.
 * @param fileId
 * @returns {`${string}${string}`}
 */
export const getFileName = (fileId) => {
  const parsedFilename = path.parse(fileId);
  return `${parsedFilename.name}${parsedFilename.ext}`;
};

export const guessMimeType = (fileId) => {
  const fileName = getFileName(fileId);
  const mimeType = mime.lookup(fileName);
  if (!mimeType && fileName === 'pdf_report') {
    return 'application/pdf';
  }
  return mimeType || 'application/octet-stream';
};

export const isFileObjectExcluded = (id) => {
  const fileName = getFileName(id);
  return excludedFiles.map((e) => e.toLowerCase()).includes(fileName.toLowerCase());
};

const filesAdaptation = (objects) => {
  const storageObjects = objects.map((obj) => {
    return {
      ...obj,
      mimeType: guessMimeType(obj.Key),
    };
  });
  return storageObjects.filter((obj) => {
    return !isFileObjectExcluded(obj.Key);
  });
};

export const loadedFilesListing = async (context, user, directory, opts = {}) => {
  const { recursive = false, callback = null, dontThrow = false } = opts;
  const files = [];
  if (isNotEmptyField(directory) && directory.startsWith('/')) {
    throw FunctionalError('File listing directory must not start with a /');
  }
  if (isNotEmptyField(directory) && !directory.endsWith('/')) {
    throw FunctionalError('File listing directory must end with a /');
  }
  const requestParams = {
    Bucket: bucketName,
    Prefix: directory,
    Delimiter: recursive ? undefined : '/'
  };
  let truncated = true;
  while (truncated) {
    try {
      const response = await s3Client.send(new s3.ListObjectsV2Command(requestParams));
      const resultFiles = filesAdaptation(response.Contents ?? []);
      const resultLoaded = await BluePromise.map(resultFiles, (f) => loadFile(context, user, f.Key, { dontThrow }), { concurrency: 5 });
      if (callback) {
        callback(resultLoaded.filter((n) => n !== undefined));
      } else {
        files.push(...resultLoaded.filter((n) => n !== undefined));
      }
      truncated = response.IsTruncated;
      if (truncated) {
        requestParams.ContinuationToken = response.NextContinuationToken;
      }
    } catch (err) {
      logApp.error(DatabaseError('[FILE STORAGE] Storage files read fail', { cause: err }));
      truncated = false;
    }
  }
  return files;
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

// Please consider using file-storage-helper#uploadToStorage() instead.
export const upload = async (context, user, filePath, fileUpload, opts) => {
  const { entity, meta = {}, noTriggerImport = false, errorOnExisting = false, file_markings = [], importContextEntities = [] } = opts;
  const metadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  const { createReadStream, filename, encoding = '' } = await fileUpload;
  const truncatedFileName = `${truncate(path.parse(filename).name, 200, false)}${truncate(path.parse(filename).ext, 10, false)}`;
  const key = `${filePath}/${truncatedFileName}`;
  const currentFile = await documentFindById(context, user, key);
  if (currentFile) {
    if (utcDate(currentFile.metaData.version).isSameOrAfter(utcDate(metadata.version))) {
      return { upload: currentFile, untouched: true };
    }
    if (errorOnExisting) {
      throw FunctionalError('A file already exists with this name');
    }
  }

  const creatorId = currentFile?.metaData?.creator_id ? currentFile.metaData.creator_id : user.id;

  // Upload the data
  const readStream = createReadStream();
  const fileMime = metadata.mimetype ?? guessMimeType(key);
  const fullMetadata = {
    ...metadata,
    filename: encodeURIComponent(truncatedFileName),
    mimetype: fileMime,
    encoding,
    creator_id: creatorId,
    entity_id: entity?.internal_id,
  };
  const s3Upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: key,
      Body: readStream
    }
  });
  await s3Upload.done();
  const fileSize = await getFileSize(user, key);

  // Register in elastic
  const file = {
    id: key,
    name: truncatedFileName,
    size: fileSize,
    information: '',
    lastModified: new Date(),
    lastModifiedSinceMin: sinceNowInMinutes(new Date()),
    metaData: { ...fullMetadata, messages: [], errors: [], file_markings },
    uploadStatus: 'complete',
  };
  await indexFileToDocument(file);

  const isFilePathForImportEnrichment = filePath.startsWith('import/') && !filePath.startsWith('import/pending');
  if (!noTriggerImport && isFilePathForImportEnrichment) {
    // Trigger import on file context entities : either specified importContextEntities or file entity or global import
    // Entities for job import can depend on context (ex: report containing the external reference)
    const jobImportContextEntities = [...importContextEntities];
    if (jobImportContextEntities.length === 0 && entity) {
      jobImportContextEntities.push(entity);
    }
    await triggerJobImport(context, user, file, jobImportContextEntities);
  }
  return { upload: file, untouched: false };
};

const triggerJobImport = async (context, user, file, contextEntities = []) => {
  if (contextEntities.length === 0) {
    // global import
    await uploadJobImport(context, user, file.id, file.metaData.mimetype, null);
  }
  // import on entities
  for (let i = 0; i < contextEntities.length; i += 1) {
    const entityContext = contextEntities[i];
    // confidence control on the context entity (like a report) if we want auto-enrichment
    // noThrow ; we do not want to fail here as it's an automatic process.
    // we will simply not start the job
    const isConfidenceMatch = entityContext ? controlUserConfidenceAgainstElement(user, entityContext, true) : true;

    // Trigger an enrich job for import file if needed
    if (isConfidenceMatch) {
      await uploadJobImport(context, user, file.id, file.metaData.mimetype, entityContext?.internal_id);
    }
  }
};

export const streamConverter = (stream) => {
  return new Promise((resolve) => {
    let data = '';
    stream.on('data', (chunk) => {
      data += chunk.toString();
    });
    stream.on('end', () => resolve(data));
  });
};
