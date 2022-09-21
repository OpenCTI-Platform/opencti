import * as s3 from '@aws-sdk/client-s3';
import * as R from 'ramda';
import { Upload } from '@aws-sdk/lib-storage';
import { Promise as BluePromise } from 'bluebird';
import { chain, CredentialsProviderError, memoize } from '@aws-sdk/property-provider';
import { remoteProvider } from '@aws-sdk/credential-provider-node/dist-cjs/remoteProvider';
import mime from 'mime-types';
import conf, { booleanConf, logApp, logAudit } from '../config/conf';
import { now, sinceNowInMinutes } from '../utils/format';
import { UPLOAD_ACTION } from '../config/audit';
import { DatabaseError } from '../config/errors';
import { createWork, deleteWorkForFile, loadExportWorksAsProgressFiles } from '../domain/work';
import { buildPagination } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';

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
    remoteProvider(init),
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

export const isStorageAlive = () => initializeBucket();

export const deleteFile = async (user, id) => {
  logApp.debug(`[FILE STORAGE] delete file ${id} by ${user.user_email}`);
  await s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  await deleteWorkForFile(user, id);
  return true;
};

export const deleteFiles = async (user, ids) => {
  logApp.debug(`[FILE STORAGE] delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    await deleteFile(user, id);
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

const streamToString = (stream) => {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
};

export const getFileContent = async (id) => {
  const object = await s3Client.send(new s3.GetObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  return streamToString(object.Body);
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
    return {
      id: filename,
      name: decodeURIComponent(object.Metadata.filename || 'unknown'),
      size: object.ContentLength,
      information: '',
      lastModified: object.LastModified,
      lastModifiedSinceMin: sinceNowInMinutes(object.LastModified),
      metaData: { ...object.Metadata, messages: [], errors: [] },
      uploadStatus: 'complete'
    };
  } catch (err) {
    if (err instanceof s3.NoSuchKey) {
      throw DatabaseError('File not found', { user_id: user.id, filename });
    }
    throw err;
  }
};

export const isFileObjectExcluded = (id) => {
  const fileName = id.includes('/') ? R.last(id.split('/')) : id;
  return excludedFiles.map((e) => e.toLowerCase()).includes(fileName.toLowerCase());
};

export const rawFilesListing = async (user, directory, recursive = false) => {
  const storageObjects = [];
  const requestParams = {
    Bucket: bucketName,
    Prefix: directory || undefined,
    Delimiter: recursive ? undefined : '/'
  };
  let truncated = true;
  while (truncated) {
    try {
      const response = await s3Client.send(new s3.ListObjectsV2Command(requestParams));
      storageObjects.push(...(response.Contents ?? []));
      truncated = response.IsTruncated;
      if (truncated) {
        requestParams.ContinuationToken = response.NextContinuationToken;
      }
    } catch (err) {
      logApp.error('[FILE STORAGE] Error loading files list', { error: err });
      truncated = false;
    }
  }
  const filteredObjects = storageObjects.filter((obj) => !isFileObjectExcluded(obj.Key));
  // Load file metadata with 5 // call maximum
  return BluePromise.map(filteredObjects, (f) => loadFile(user, f.Key), { concurrency: 5 });
};

export const uploadJobImport = async (user, fileId, fileMime, entityId, opts = {}) => {
  const { manual = false, connectorId = null, bypassValidation = false } = opts;
  let connectors = await connectorsForImport(user, fileMime, true, !manual);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (!entityId) {
    connectors = R.filter((n) => !n.only_contextual, connectors);
  }
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector) => {
      const work = await createWork(user, connector, 'Manual import', fileId);
      return { connector, work };
    };
    const actionList = await Promise.all(R.map((connector) => createConnectorWork(connector), connectors));
    // Send message to all correct connectors queues
    const buildConnectorMessage = (data) => {
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
      };
    };
    const pushMessage = (data) => {
      const { connector } = data;
      const message = buildConnectorMessage(data);
      return pushToConnector(connector, message);
    };
    await Promise.all(R.map((data) => pushMessage(data), actionList));
  }
};

export const upload = async (user, path, fileUpload, meta = {}, noTriggerImport = false) => {
  const { createReadStream, filename, mimetype, encoding = '' } = await fileUpload;
  // Upload the data
  const readStream = createReadStream();
  const fileMime = mime.lookup(filename) || mimetype;
  const metadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  logAudit.info(user, UPLOAD_ACTION, { path, filename, metadata });
  const key = `${path}/${filename}`;
  const fullMetadata = {
    ...metadata,
    filename: encodeURIComponent(filename),
    mimetype: fileMime,
    encoding,
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
    await uploadJobImport(user, file.id, file.metaData.mimetype, file.metaData.entity_id);
  }
  return file;
};

export const filesListing = async (user, first, path, entityId = null) => {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = R.concat(inExport, files);
  const sortedFiles = R.sort((a, b) => b.lastModified - a.lastModified, allFiles);
  let fileNodes = R.map((f) => ({ node: f }), sortedFiles);
  if (entityId) {
    fileNodes = R.filter((n) => n.node.metaData.entity_id === entityId, fileNodes);
  }
  return buildPagination(first, null, fileNodes, allFiles.length);
};

export const deleteAllFiles = async (user, path) => {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = R.concat(inExport, files);
  const ids = allFiles.map((file) => file.id);
  return deleteFiles(user, ids);
};
