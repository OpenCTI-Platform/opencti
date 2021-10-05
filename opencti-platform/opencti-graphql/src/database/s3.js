// import * as S3 from 'S3';
import * as He from 'he';
import { concat, map, sort } from 'ramda';
import querystring from 'querystring';
import {
  S3Client,
  ListBucketsCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import conf, { /* booleanConf, */ logApp, logAudit } from '../config/conf';
import { buildPagination } from './utils';
import { loadExportWorksAsProgressFiles, deleteWorkForFile } from '../domain/work';
import { sinceNowInMinutes } from '../utils/format';
import { DatabaseError } from '../config/errors';
import { UPLOAD_ACTION } from '../config/audit';

const s3AccessKeyId = conf.get('s3:access_key');
const s3SecretAccessKey = conf.get('s3:secret_key');
const s3BucketName = conf.get('s3:bucket_name');
const s3Region = conf.get('s3:region');

const s3Client = new S3Client({
  region: s3Region,
  credentials: { accessKeyId: s3AccessKeyId, secretAccessKey: s3SecretAccessKey },
});

const bucketExists = async () => {
  const command = new ListBucketsCommand({ bucketName: s3BucketName, bucketRegion: s3Region });
  const response = await s3Client.send(command);
  const code = response.$metadata.httpStatusCode;
  if (code < 200 || code > 399) {
    throw new Error('Bad response checking bucket existence.');
  }
  if (!response.Buckets.map((b) => b.Name).includes(s3BucketName)) {
    logApp.error(`[S3] Bucket ${s3BucketName} does not exist.`);
    throw new Error('Configured bucket does not exist.');
  }
};

export const isStorageAlive = async () => {
  await bucketExists();
};

export const deleteFile = async (user, id) => {
  logApp.debug(`[S3] Delete file ${id} by ${user.user_email}`);
  const command = new DeleteObjectCommand({ Bucket: s3BucketName, Key: id });
  const response = await s3Client.send(command);
  const code = response.$metadata.httpStatusCode;
  if (code < 200 || code > 399) {
    logApp.error(`[S3] Delete file failed for ${id} by ${user.user_email}`);
    return;
  }
  await deleteWorkForFile(user, id);
};

export const downloadFile = (id) => {
  try {
    const command = new GetObjectCommand({ Bucket: s3BucketName, Key: id });
    return s3Client.send(command).then((response) => {
      const code = response.$metadata.httpStatusCode;
      if (code < 200 || code > 399) {
        logApp.error(`[S3] Delete file failed for ${id}`);
        throw new Error(`Failed to download file ${id}`);
      }
      return response.Body;
    });
  } catch (err) {
    logApp.info(`[OPENCTI] Cannot retrieve file on S3`, { error: err });
    return null;
  }
};

export const getFileContent = (id) => {
  return new Promise((resolve, reject) => {
    let str = '';
    downloadFile(id).then((stream) => {
      stream.on('data', (data) => {
        str += data.toString('utf-8');
      });
      stream.on('end', () => {
        resolve(str);
      });
      stream.on('error', (error) => {
        reject(error);
      });
    });
  });
};

export const loadFile = async (user, filename) => {
  try {
    const command = new HeadObjectCommand({ Bucket: s3BucketName, Key: filename });
    const response = await s3Client.send(command);
    const code = response.$metadata.httpStatusCode;
    if (code < 200 || code > 399) {
      // logApp.error(`[S3] Delete file failed for ${id} by ${user.user_email}`);
      throw new Error();
    }
    return {
      id: filename,
      name: querystring.unescape(filename),
      size: response.ContentLength,
      information: '',
      lastModified: response.LastModified,
      lastModifiedSinceMin: sinceNowInMinutes(response.LastModified),
      metaData: {
        // TODO: Extract metadata from would-be-header values starting with 'x-amz-meta-(eg. storage-class)' and others... (https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html, https://github.com/minio/minio-js/blob/99f8d56332639feb8c573670df50581e538f59f4/src/main/helpers.js#L348)
        messages: [],
        errors: [],
      },
      uploadStatus: 'complete',
    };
  } catch (err) {
    throw DatabaseError('File not found', { user_id: user.id, filename });
  }
};

const rawFilesListing = (user, directory) => {
  return new Promise((resolve, reject) => {
    // Use if needing to remove directory structure from key/name: const dirlen = directory.length + directory.endsWith('/') ? 1 : 0;
    const command = new ListObjectsV2Command({ Bucket: s3BucketName, Prefix: directory });
    s3Client
      .send(command)
      // eslint-disable-next-line consistent-return
      .then((response) => {
        if (response.KeyCount === 0) resolve([]);
        resolve(response.Contents.map((obj) => obj.Key));
      })
      .catch((err) => {
        logApp.error('[S3] Error listing files', { error: err });
        reject(err);
      });
  }).then((files) => {
    return Promise.all(
      map((elem) => {
        const filename = He.decode(elem.name);
        return loadFile(user, filename);
      }, files)
    );
  });
};

export const upload = async (user, path, file, metadata = {}) => {
  const { createReadStream, filename, mimetype, encoding, contentLength } = await file;
  logAudit.info(user, UPLOAD_ACTION, { path, filename, metadata });
  // const escapeName = querystring.escape(filename);
  // const internalMeta = { filename: escapeName, mimetype, encoding };
  // const fileMeta = { ...metadata, ...internalMeta };
  const fileDirName = `${path}/${filename}`;
  logApp.debug(`[S3] Upload file ${fileDirName} by ${user.user_email}`);
  // Upload the file in the storage
  return new Promise((resolve, reject) => {
    const command = new PutObjectCommand({
      Bucket: s3BucketName,
      Key: fileDirName,
      ContentLength: contentLength,
      ContentType: mimetype,
      ContentEncoding: encoding,
      Body: createReadStream(),
    });
    s3Client
      .send(command)
      .then(() => {
        resolve(loadFile(user, fileDirName));
      })
      .catch((err) => {
        reject(err);
      });
  });
};

export const filesListing = async (user, first, path) => {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = concat(inExport, files);
  const sortedFiles = sort((a, b) => b.lastModified - a.lastModified, allFiles);
  const fileNodes = map((f) => ({ node: f }), sortedFiles);
  return buildPagination(first, null, fileNodes, allFiles.length);
};

export const deleteAllFiles = async (user, path) => {
  const files = await rawFilesListing(user, path);
  const inExport = await loadExportWorksAsProgressFiles(user, path);
  const allFiles = concat(inExport, files);
  return Promise.all(allFiles.map((file) => deleteFile(user, file.id)));
};
