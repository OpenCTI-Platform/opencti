import * as s3 from '@aws-sdk/client-s3';
import * as R from 'ramda';
import path from 'node:path';
import { Upload } from '@aws-sdk/lib-storage';
import { Promise as BluePromise } from 'bluebird';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import mime from 'mime-types';
import conf, { booleanConf, ENABLED_FILE_INDEX_MANAGER, logApp } from '../config/conf';
import { now, sinceNowInMinutes, truncate, utcDate } from '../utils/format';
import { DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import { createWork, deleteWorkForFile, deleteWorkForSource } from '../domain/work';
import { isNotEmptyField } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';
import { elDeleteFilesByIds } from './file-search';
import { isAttachmentProcessorEnabled } from './engine';
import { allFilesForPaths, deleteDocumentIndex, findById as documentFindById, indexFileToDocument } from '../modules/internal/document/document-domain';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';

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

export const specialTypesExtensions = {
  'application/vnd.oasis.stix+json': 'json',
  'application/vnd.mitre.navigator+json': 'json',
};

const credentialProvider = () => {
  if (useAwsRole) {
    return defaultProvider({
      roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity({
        // You must explicitly pass a region if you are not using us-east-1
        region: bucketRegion
      })
    });
  }
  return {
    accessKeyId: clientAccessKey,
    secretAccessKey: clientSecretKey,
    ...(clientSessionToken && { sessionToken: clientSessionToken })
  };
};

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
    logApp.info(`[FILE STORAGE] delete file ${id} in index`);
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

export const loadFile = async (user, filename, opts = {}) => {
  const { dontThrow = false } = opts;
  try {
    const object = await s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: filename
    }));
    const metaData = {
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
    return {
      id: filename,
      name: decodeURIComponent(object.Metadata.filename || 'unknown'),
      size: object.ContentLength,
      information: '',
      lastModified: object.LastModified,
      lastModifiedSinceMin: sinceNowInMinutes(object.LastModified),
      uploadStatus: 'complete',
      metaData,
    };
  } catch (err) {
    if (dontThrow) {
      logApp.error('Load file from storage fail', { cause: err, user_id: user.id, filename });
      return undefined;
    }
    throw UnsupportedError('Load file from storage fail', { cause: err, user_id: user.id, filename });
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

export const loadedFilesListing = async (user, directory, opts = {}) => {
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
      const resultLoaded = await BluePromise.map(resultFiles, (f) => loadFile(user, f.Key, { dontThrow }), { concurrency: 5 });
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
      logApp.error(DatabaseError('Storage files read fail', { cause: err }));
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

export const upload = async (context, user, filePath, fileUpload, opts) => {
  const { entity, meta = {}, noTriggerImport = false, errorOnExisting = false } = opts;
  const metadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  const { createReadStream, filename, mimetype, encoding = '' } = await fileUpload;
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
  const fileMime = guessMimeType(key) || mimetype;
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
      Body: readStream,
      Metadata: fullMetadata
    }
  });
  await s3Upload.done();
  const uploadedFile = await loadFile(user, key);

  // Register in elastic
  const file = {
    id: key,
    name: truncatedFileName,
    size: uploadedFile.size,
    information: '',
    lastModified: new Date(),
    lastModifiedSinceMin: sinceNowInMinutes(new Date()),
    metaData: { ...fullMetadata, messages: [], errors: [] },
    uploadStatus: 'complete'
  };
  await indexFileToDocument(file);

  // confidence control on the context entity (like a report) if we want auto-enrichment
  // noThrow ; we do not want to fail here as it's an automatic process.
  // we will simply not start the job
  const isConfidenceMatch = entity ? controlUserConfidenceAgainstElement(user, entity, true) : true;
  const isFilePathForImportEnrichment = filePath.startsWith('import/')
    && !filePath.startsWith('import/pending')
    && !filePath.startsWith('import/External-Reference');

  // Trigger an enrich job for import file if needed
  if (!noTriggerImport && isConfidenceMatch && isFilePathForImportEnrichment) {
    await uploadJobImport(context, user, file.id, file.metaData.mimetype, file.metaData.entity_id);
  }
  return { upload: file, untouched: false };
};

export const deleteAllObjectFiles = async (context, user, element) => {
  const importPath = `import/${element.entity_type}/${element.internal_id}`;
  const importFilesPromise = allFilesForPaths(context, user, [importPath]);
  const importWorkPromise = deleteWorkForSource(importPath);
  const exportPath = `export/${element.entity_type}/${element.internal_id}`;
  const exportFilesPromise = allFilesForPaths(context, user, [exportPath]);
  const exportWorkPromise = deleteWorkForSource(exportPath);
  const [importFiles, exportFiles, _, __] = await Promise.all([
    importFilesPromise,
    exportFilesPromise,
    importWorkPromise,
    exportWorkPromise
  ]);
  const ids = [...importFiles, ...exportFiles].map((file) => file.id);
  return deleteFiles(context, user, ids);
};
