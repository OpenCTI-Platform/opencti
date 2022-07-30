import * as s3 from '@aws-sdk/client-s3';
import * as R from 'ramda';
import * as He from 'he';
import { Upload } from "@aws-sdk/lib-storage";
import { chain, CredentialsProviderError, memoize } from '@aws-sdk/property-provider';
import { remoteProvider } from '@aws-sdk/credential-provider-node/dist-cjs/remoteProvider';
import { join as joinPaths } from 'path';
import conf, { booleanConf, logApp, logAudit } from '../config/conf';
import { now, sinceNowInMinutes } from '../utils/format';
import { UPLOAD_ACTION } from '../config/audit';
import { DatabaseError } from '../config/errors';
import { deleteWorkForFile, loadExportWorksAsProgressFiles } from '../domain/work';
import { buildPagination } from './utils';

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

const credentialProvider = (init) => memoize(
  chain(
    async () => {
      if (clientAccessKey && clientSecretKey && clientAccessKey != "ChangeMe" && clientSecretKey != "ChangeMe") {
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

const s3Client = new s3.S3Client({
  region: bucketRegion,
  endpoint: getEndpoint(),
  forcePathStyle: true,
  credentialDefaultProvider: credentialProvider,
  tls: useSslConnection
});

function getEndpoint() {
  // If using AWS S3, unset the endpoint to let the library choose the best endpoint
  if (clientEndpoint == 's3.amazonaws.com') {
    return undefined;
  }

  let endpoint = useSslConnection ? 'https://' : 'http://';
  endpoint += clientEndpoint;
  if (clientPort) {
    endpoint += `:${clientPort}`;
  }

  return endpoint;
}

export async function initializeBucket() {
  try {
    await s3Client.send(new s3.CreateBucketCommand({
      Bucket: bucketName
    }));
    return true;
  } catch (err) {
    if (err instanceof s3.BucketAlreadyOwnedByYou) {
      return true;
    }

    if (err instanceof s3.BucketAlreadyExists) {
      throw new Error(`The S3 bucket name ${bucketName} is already in use, please choose another.`);
    }

    throw err;
  }
}

export async function isStorageAlive() {
  return initializeBucket();
}

export async function deleteFile(user, id) {
  logApp.debug(`[MINIO] delete file ${id} by ${user.user_email}`);
  await s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
  }));
  await deleteWorkForFile(user, id);
  return true;
}

export async function deleteFiles(user, ids) {
  logApp.debug(`[MINIO] delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    await deleteFile(user, id);
  }
  return true;
}

export async function downloadFile(id) {
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
}

function streamToString(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

export async function getFileContent(id) {
  const object = await s3Client.send(new s3.GetObjectCommand({
    Bucket: bucketName,
    Key: id
  }));

  return streamToString(object.Body);
}

export function storeFileConverter(user, file) {
  return {
    id: file.id,
    name: file.name,
    version: file.metaData.version,
    mime_type: file.metaData.mimetype,
  };
}

export async function loadFile(user, filename) {
  try {
    const object = await s3Client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: filename
    }));

    return {
      id: filename,
      name: He.decode(object.Metadata.filename || 'unknown'),
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
}

export function isFileObjectExcluded(id) {
  const fileName = id.includes('/') ? R.last(id.split('/')) : id;
  return excludedFiles.map((e) => e.toLowerCase()).includes(fileName.toLowerCase());
}

export async function rawFilesListing(user, directory, recursive = false) {
  let truncated = true;
  let pageMarker;
  const objects = [];
  const requestParams = {
    Bucket: bucketName,
    Prefix: directory || undefined
  };

  while (truncated) {
    const response = await s3Client.send(new s3.ListObjectsV2Command(requestParams));

    if (!response.Contents) {
      truncated = false;
      break;
    }

    objects.push(...response.Contents);
    truncated = response.IsTruncated;
    if (truncated) {
      pageMarker = response.Contents.slice(-1)[0].Key;
      requestParams.Marker = pageMarker;
    }
  }

  return objects.reduce(async (items, item) => {
    if (!isFileObjectExcluded(item.Key)) {
      items.push(await loadFile(user, item.Key));
    }
    return items;
  }, []);
}

export async function upload(user, path, fileUpload, metadata = {}) {
  const { createReadStream, filename, mimetype, encoding = '', version = now() } = await fileUpload;
  const readStream = createReadStream();

  logAudit.info(user, UPLOAD_ACTION, { path, filename, metadata });

  const key = joinPaths(path, filename);
  const fullMetadata = {
    ...metadata,
    filename: He.encode(filename),
    mimetype,
    encoding,
    version
  };

  const upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: key,
      Body: readStream,
      Metadata: fullMetadata
    }
  });
  await upload.done();

  return {
    id: key,
    name: filename,
    size: readStream.bytesRead,
    information: '',
    lastModified: new Date(),
    lastModifiedSinceMin: sinceNowInMinutes(new Date()),
    metaData: { ...fullMetadata, messages: [], errors: [] },
    uploadStatus: 'complete'
  };
}

export async function filesListing(user, first, path, entityId = null) {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = R.concat(inExport, files);
  const sortedFiles = R.sort((a, b) => b.lastModified - a.lastModified, allFiles);
  let fileNodes = R.map((f) => ({ node: f }), sortedFiles);
  if (entityId) {
    fileNodes = R.filter((n) => n.node.metaData.entity_id === entityId, fileNodes);
  }
  return buildPagination(first, null, fileNodes, allFiles.length);
}

export async function deleteAllFiles(user, path) {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = R.concat(inExport, files);
  const ids = allFiles.map((file) => file.id);
  return deleteFiles(user, ids);
}
