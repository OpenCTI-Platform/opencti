import * as s3 from '@aws-sdk/client-s3';
import { CopyObjectCommand } from '@aws-sdk/client-s3';
import * as R from 'ramda';
import path from 'node:path';
import { Upload } from '@aws-sdk/lib-storage';
import { Promise as BluePromise } from 'bluebird';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import mime from 'mime-types';
import nconf from 'nconf';
import conf, { booleanConf, logApp, logS3Debug } from '../config/conf';
import { now, sinceNowInMinutes, truncate, utcDate } from '../utils/format';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { createWork, deleteWorkForFile } from '../domain/work';
import { isNotEmptyField, READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';
import { elDeleteFilesByIds } from './file-search';
import { isAttachmentProcessorEnabled } from './engine';
import {
  deleteDocumentIndex,
  EMBEDDED_STORAGE_PATH,
  EXPORT_STORAGE_PATH,
  findById as documentFindById,
  FROM_TEMPLATE_STORAGE_PATH,
  IMPORT_STORAGE_PATH,
  indexFileToDocument,
  SUPPORT_STORAGE_PATH
} from '../modules/internal/document/document-domain';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { enrichWithRemoteCredentials } from '../config/credentials';
import { isUserHasCapability, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, SETTINGS_SUPPORT, validateMarking } from '../utils/access';
import { internalLoadById } from './middleware-loader';
import { getDraftContext } from '../utils/draftContext';
import { isModuleActivated } from './cluster-module';
import { getDraftFilePrefix, isDraftFile } from './draft-utils';

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
const disableChecksumValidation = booleanConf('minio:disable_checksum_validation', false);
export const defaultValidationMode = conf.get('app:validation_mode');

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
    tls: useSslConnection,
    requestChecksumCalculation: disableChecksumValidation ? 'WHEN_REQUIRED' : 'WHEN_SUPPORTED',
    responseChecksumValidation: disableChecksumValidation ? 'WHEN_REQUIRED' : 'WHEN_SUPPORTED'
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

export const deleteFileFromStorage = async (id) => {
  return s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
};

export const deleteFile = async (context, user, id) => {
  const draftContext = getDraftContext(context, user);
  if (draftContext && !isDraftFile(id, draftContext)) {
    throw UnsupportedError('Cannot delete non draft imports in draft', { id });
  }
  const up = await loadFile(context, user, id);
  logApp.debug(`[FILE STORAGE] delete file ${id} by ${user.user_email}`);
  // Delete in S3
  await deleteFileFromStorage(id);
  // Delete associated works
  await deleteWorkForFile(context, user, id);
  // Delete index file
  await deleteDocumentIndex(context, user, id);
  // delete in index if file has been indexed
  const isFileIndexModuleActivated = await isModuleActivated('FILE_INDEX_MANAGER');
  if (isFileIndexModuleActivated && isAttachmentProcessorEnabled()) {
    logApp.debug(`[FILE STORAGE] delete file ${id} in index`);
    await elDeleteFilesByIds([id])
      .catch((err) => {
        logApp.error('[FILE STORAGE] Error deleting file', { cause: err });
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

export const deleteRawFiles = async (context, user, ids) => {
  logApp.debug(`[FILE STORAGE] raw delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    // Delete in S3
    await deleteFileFromStorage(id);
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
    logApp.error('[FILE STORAGE] Cannot retrieve file from S3', { cause: err, fileId: id });
    return null;
  }
};

/**
 * - Copy file from a place to another in S3
 * - Store file in documents
 * @param context
 * @param user
 * @param {{sourceId: string, targetId: string, sourceDocument: BasicStoreEntityDocument, targetEntityId: string}} copyProps
 * @returns {Promise<null|File>} the document entity on success, null on errors.
 */
export const copyFile = async (context, copyProps) => {
  const { sourceId, targetId, sourceDocument, targetEntityId } = copyProps;
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
    await indexFileToDocument(context, file);
    logApp.info('[FILE STORAGE] Copy file to S3 in success', { document: file, sourceId, targetId });
    return file;
  } catch (err) {
    logApp.error('[FILE STORAGE] Cannot copy file in S3', { cause: err, sourceId, targetId });
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
    file_markings: file.metaData.file_markings ?? [],
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
  try {
    if (!fileS3Path) {
      throw FunctionalError('File path not specified');
    }
    // 01. Check if user as enough capability to get support packages
    if (fileS3Path.startsWith(SUPPORT_STORAGE_PATH) && !isUserHasCapability(user, SETTINGS_SUPPORT)) {
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 01.1. Check if user as enough capability to load import / export / template knowledge files
    if ((fileS3Path.startsWith(IMPORT_STORAGE_PATH)
        || fileS3Path.startsWith(EMBEDDED_STORAGE_PATH)
        || fileS3Path.startsWith(EXPORT_STORAGE_PATH)
        || fileS3Path.startsWith(FROM_TEMPLATE_STORAGE_PATH))
      && !isUserHasCapability(user, KNOWLEDGE)) {
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 01.2. Check if user as enough capability to load import/global files
    if (fileS3Path.startsWith(`${IMPORT_STORAGE_PATH}/global`) && !isUserHasCapability(user, KNOWLEDGE_KNASKIMPORT)) {
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 02. Check if the referenced document is accessible
    const document = await documentFindById(context, user, fileS3Path, { ignoreDuplicates: true });
    if (!document) {
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 03. Check if metadata contains an entity_id, we need to check if the user has real access to this instance
    const { metaData } = document;
    if (metaData.entity_id) {
      if (!isUserHasCapability(user, KNOWLEDGE)) {
        throw FunctionalError('File not found or restricted', { filename: fileS3Path });
      }
      const instance = await internalLoadById(context, user, metaData.entity_id, { indices: [...READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS] });
      if (!instance) {
        throw FunctionalError('File not found or restricted', { filename: fileS3Path });
      }
    }
    // All good, return the file
    return {
      ...document,
      id: fileS3Path,
      information: '',
      uploadStatus: 'complete',
      metaData
    };
  } catch (err) {
    if (opts.dontThrow) {
      return undefined;
    }
    throw err;
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

/**
 * Get file mime type from filename
 * @param fileId the complete path with filename
 * @returns {string}
 */
export const guessMimeType = (fileId) => {
  const fileName = getFileName(fileId);
  const mimeType = mime.lookup(fileName);
  // If type is not found
  if (!mimeType) {
    // Try static resolutions
    const appMimes = nconf.get('app:filename_to_mimes') || {};
    const mimeEntries = Object.entries(appMimes);
    for (let index = 0; index < mimeEntries.length; index += 1) {
      const [key, val] = mimeEntries[index];
      if (fileName.endsWith(key)) {
        return val;
      }
    }
    // If nothing static found, return basic octet-stream
    return 'application/octet-stream';
  }
  return mimeType;
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
    throw FunctionalError('File listing directory must not start with a /', { directory });
  }
  if (isNotEmptyField(directory) && !directory.endsWith('/')) {
    throw FunctionalError('File listing directory must end with a /', { directory });
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
      logApp.error('[FILE STORAGE] Storage files read fail', { cause: err });
      truncated = false;
    }
  }
  return files;
};

export const uploadJobImport = async (context, user, file, entityId, opts = {}) => {
  const {
    manual = false,
    connectorId = null,
    configuration = null,
    bypassValidation = false,
    validationMode = defaultValidationMode,
    forceValidation = false
  } = opts;
  const draftContext = getDraftContext(context, user);
  let connectors = await connectorsForImport(context, user, file.metaData.mimetype, true, !manual);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (!entityId) {
    connectors = R.filter((n) => !n.only_contextual, connectors);
  }
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector) => {
      const contextOutOfDraft = { ...context, draft_context: '' };
      const messageToUse = draftContext ? `Manual import of ${file.name} in draft ${draftContext}` : `Manual import of ${file.name}`;
      const work = await createWork(contextOutOfDraft, user, connector, messageToUse, file.id, { draftContext });
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
          draft_id: draftContext ?? null, // If we are in a draft, import in current draft context
          trigger: 'update',
          mode: 'auto'
        },
        event: {
          file_id: file.id,
          file_mime: file.metaData.mimetype,
          file_markings: file.metaData.file_markings ?? [],
          file_fetch: `/storage/get/${file.id}`, // Path to get the file
          entity_id: entityId, // Context of the upload*
          validation_mode: draftContext ? 'draft' : validationMode, // Force to draft if we are in draft
          bypass_validation: draftContext ? true : bypassValidation, // Force no validation: always force it when in draft
          force_validation: forceValidation, // Force validation
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
  // Verify markings
  for (let index = 0; index < (file_markings ?? []).length; index += 1) {
    const markingId = file_markings[index];
    await validateMarking(context, user, markingId);
  }
  const metadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  const { createReadStream, filename, encoding = '' } = await fileUpload;
  const truncatedFileName = `${truncate(path.parse(filename).name, 200, false)}${truncate(path.parse(filename).ext, 10, false)}`;
  // We lowercase the file name to make it case-insensitive
  let key = `${filePath}/${truncatedFileName.toLowerCase()}`;
  // In draft, we add a prefix to file path
  const draftContext = getDraftContext(context, user);
  if (draftContext) {
    const draftPrefix = getDraftFilePrefix(draftContext);
    key = `${draftPrefix}${key}`;
  }
  const currentFile = await documentFindById(context, user, key);
  if (currentFile) {
    // If file exists, we want to use it's internal_id to use the same casing and keep it compatible
    key = currentFile.internal_id;
    if (utcDate(currentFile.metaData.version).isSameOrAfter(utcDate(metadata.version))) {
      return { upload: currentFile, untouched: true };
    }
    if (errorOnExisting) {
      throw FunctionalError('A file already exists with this name', { truncatedFileName });
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
  await indexFileToDocument(context, file);

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
    await uploadJobImport(context, user, file, null);
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
      await uploadJobImport(context, user, file, entityContext?.internal_id);
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
