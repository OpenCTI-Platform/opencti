import path, { join } from 'node:path';
import mime from 'mime-types';
import nconf from 'nconf';
import type { _Object } from '@aws-sdk/client-s3';
import fs from 'node:fs';
import { Readable } from 'stream';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntityDocument } from '../modules/internal/document/document-types';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreObject } from '../types/store';
import type { BasicStoreEntityConnector } from '../types/connector';
import conf, { logApp } from '../config/conf';
import { now, sinceNowInMinutes, truncate, utcDate } from '../utils/format';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { createWork, deleteWorkForFile, deleteWorkForSource } from '../domain/work';
import { isNotEmptyField, READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS } from './utils';
import { connectorsForImport } from './repository';
import { pushToConnector } from './rabbitmq';
import { elDeleteFilesByIds } from './file-search';
import { isAttachmentProcessorEnabled } from './engine';
import {
  allFilesForPaths,
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
import { isUserHasCapability, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, SETTINGS_SUPPORT, validateMarking } from '../utils/access';
import { internalLoadById } from './middleware-loader';
import { getDraftContext } from '../utils/draftContext';
import { isModuleActivated } from './cluster-module';
import { getDraftFilePrefix, isDraftFile } from './draft-utils';
import { deleteFileFromStorage, getFileSize, rawCopyFile, rawListObjects, rawUpload } from './raw-file-storage';
import { promiseMap } from '../utils/promiseUtils';
import { ENTITY_TYPE_SUPPORT_PACKAGE } from '../modules/support/support-types';

// Minio configuration
const excludedFiles = conf.get('minio:excluded_files') || ['.DS_Store'];
export const defaultValidationMode = conf.get('app:validation_mode');

export const specialTypesExtensions = {
  'application/vnd.oasis.stix+json': 'json',
  'application/vnd.mitre.navigator+json': 'json',
};

/**
 * Runtime metadata structure for file manipulation.
 * More flexible than BasicStoreEntityDocument.metaData for internal processing.
 * Includes runtime-only fields (messages, errors, creator_id) not persisted in DB.
 * Not exported - internal to file-storage operations.
 */
interface FileMetadata {
  [key: string]: string | number | boolean | string[] | undefined;
  version?: string;
  mimetype?: string;
  encoding?: string;
  filename?: string;
  creator_id?: string;
  entity_id?: string;
  messages?: string[];
  errors?: string[];
  file_markings?: string[];
  order?: number;
  description?: string;
  inCarousel?: boolean;
}

/**
 * Unified structure representing a loaded file with all its information.
 * Used as the primary exchange format for file operations throughout the application.
 */
export interface LoadedFile {
  id: string;
  name: string;
  size: number | undefined;
  information: string;
  lastModified: Date;
  lastModifiedSinceMin: Date | number;
  metaData: FileMetadata;
  uploadStatus: string;
  internal_id?: string;
}

/**
 * Simplified structure for raw S3 objects.
 * Used internally for S3 object transformations before loading full file metadata.
 * Not exported - internal to file-storage operations.
 */
interface S3FileObject {
  Key: string;
  mimeType: string;
}

/**
 * Get file metadata from database, or else from S3.
 */
export const loadFile = async (
  context: AuthContext,
  user: AuthUser,
  fileS3Path: string,
  opts: { dontThrow?: boolean } = {}
): Promise<LoadedFile | undefined> => {
  try {
    if (!fileS3Path) {
      throw FunctionalError('File path not specified');
    }
    // 01. Check if user as enough capability to get support packages
    if (fileS3Path.startsWith(SUPPORT_STORAGE_PATH) && !isUserHasCapability(user, SETTINGS_SUPPORT)) {
      if (opts.dontThrow) {
        return undefined;
      }
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 01.1. Check if user as enough capability to load import / export / template knowledge files
    if ((fileS3Path.startsWith(IMPORT_STORAGE_PATH)
        || fileS3Path.startsWith(EMBEDDED_STORAGE_PATH)
        || fileS3Path.startsWith(EXPORT_STORAGE_PATH)
        || fileS3Path.startsWith(FROM_TEMPLATE_STORAGE_PATH))
      && !isUserHasCapability(user, KNOWLEDGE)) {
      if (opts.dontThrow) {
        return undefined;
      }
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 01.2. Check if user as enough capability to load import/global files
    if (fileS3Path.startsWith(`${IMPORT_STORAGE_PATH}/global`) && !isUserHasCapability(user, KNOWLEDGE_KNASKIMPORT)) {
      if (opts.dontThrow) {
        return undefined;
      }
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 02. Check if the referenced document is accessible
    const document = await documentFindById(context, user, fileS3Path, { ignoreDuplicates: true });
    if (!document) {
      if (opts.dontThrow) {
        return undefined;
      }
      throw FunctionalError('File not found or restricted', { filename: fileS3Path });
    }
    // 03. Check if metadata contains an entity_id, we need to check if the user has real access to this instance
    const { metaData } = document;
    if (metaData.entity_id) {
      if (!isUserHasCapability(user, KNOWLEDGE)) {
        if (opts.dontThrow) {
          return undefined;
        }
        throw FunctionalError('File not found or restricted', { filename: fileS3Path });
      }
      const instance = await internalLoadById(context, user, metaData.entity_id, { indices: [...READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS] });
      if (!instance) {
        if (opts.dontThrow) {
          return undefined;
        }
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
    } as LoadedFile;
  } catch (err) {
    if (opts.dontThrow) {
      return undefined;
    }
    throw err;
  }
};

/**
 * Deletes a file from storage, removing it from S3, associated works, document index, and file index.
 * Validates draft context restrictions before deletion.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user performing the deletion
 * @param {string} id - The file ID (S3 path) to delete
 * @returns {Promise<LoadedFile | undefined>} The deleted file information
 * @throws {UnsupportedError} When attempting to delete non-draft files in draft mode
 */
export const deleteFile = async (context: AuthContext, user: AuthUser, id: string) => {
  const draftContext = getDraftContext(context, user);
  if (draftContext && !isDraftFile(id, draftContext)) {
    throw UnsupportedError('Cannot delete non draft imports in draft');
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

/**
 * Batch deletion of multiple files by calling deleteFile for each ID.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user performing the deletions
 * @param {string[]} ids - Array of file IDs to delete
 * @returns {Promise<boolean>} True when all deletions complete
 */
export const deleteFiles = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  logApp.debug(`[FILE STORAGE] delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    await deleteFile(context, user, id);
  }
  return true;
};

/**
 * Performs raw deletion of files from S3 storage only, without cleaning up indexes or works.
 * Use this for cleanup operations where metadata has already been handled.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user performing the deletions
 * @param {string[]} ids - Array of file IDs to delete from S3
 * @returns {Promise<boolean>} True when all deletions complete
 */
export const deleteRawFiles = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  logApp.debug(`[FILE STORAGE] raw delete files ${ids} by ${user.user_email}`);
  for (let i = 0; i < ids.length; i += 1) {
    const id = ids[i];
    // Delete in S3
    await deleteFileFromStorage(id);
  }
  return true;
};

/**
 * - Copy file from a place to another in S3
 * - Store file in documents
 * @param context
 * @param copyProps
 * @returns the document entity on success, null on errors.
 */
export const copyFile = async (
  context: AuthContext,
  copyProps: { sourceId: string; targetId: string; sourceDocument: BasicStoreEntityDocument; targetEntityId: string }
): Promise<LoadedFile | null> => {
  const { sourceId, targetId, sourceDocument, targetEntityId } = copyProps;
  try {
    await rawCopyFile(sourceId, targetId);
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

/**
 * Convert File object coming from uploadToStorage/upload functions to x_opencti_file format.
 */
export const storeFileConverter = (user: AuthUser, file: LoadedFile) => {
  return {
    id: file.id,
    name: file.name,
    version: file.metaData.version,
    mime_type: file.metaData.mimetype,
    file_markings: file.metaData.file_markings ?? [],
  };
};

/**
 * Get (filename + extension) from S3 file full path.
 * @param fileId
 * @returns {`${string}${string}`}
 */
export const getFileName = (fileId: string): string => {
  const parsedFilename = path.parse(fileId);
  return `${parsedFilename.name}${parsedFilename.ext}`;
};

/**
 * Get file mime type from filename
 * @param fileId the complete path with filename
 * @returns {string}
 */
export const guessMimeType = (fileId: string): string => {
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
        return val as string;
      }
    }
    // If nothing static found, return basic octet-stream
    return 'application/octet-stream';
  }
  return mimeType;
};

/**
 * Checks if a file should be excluded based on the excluded files configuration.
 * Performs case-insensitive comparison against the configured exclusion list.
 * @param {string} id - The file ID or path to check
 * @returns {boolean} True if the file should be excluded, false otherwise
 */
export const isFileObjectExcluded = (id: string): boolean => {
  const fileName = getFileName(id);
  return excludedFiles.map((e: string) => e.toLowerCase()).includes(fileName.toLowerCase());
};

/**
 * Transforms raw S3 objects into S3FileObject format with mime type detection.
 * Filters out objects without keys and applies exclusion rules.
 * @param {_Object[]} objects - Array of raw S3 objects from AWS SDK
 * @returns {S3FileObject[]} Filtered and transformed array of S3 file objects with mime types
 */
const filesAdaptation = (objects: _Object[]): S3FileObject[] => {
  const storageObjects = objects
    .filter((obj): obj is Required<Pick<_Object, 'Key'>> & _Object => obj.Key !== undefined)
    .map((obj) => {
      return {
        Key: obj.Key,
        mimeType: guessMimeType(obj.Key),
      };
    });
  return storageObjects.filter((obj: S3FileObject) => {
    return !isFileObjectExcluded(obj.Key);
  });
};

/**
 * Lists and loads files from a directory with support for recursive listing and pagination.
 * Handles S3 pagination automatically and validates directory format.
 * Optionally invokes a callback for streaming results or accumulates all files.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user requesting the file listing
 * @param {string} directory - The directory path to list (must end with /, must not start with /)
 * @param {Object} opts - Optional configuration
 * @param {boolean} opts.recursive - Whether to list files recursively (default: false)
 * @param {Function} opts.callback - Optional callback to process files in batches
 * @param {boolean} opts.dontThrow - Whether to suppress errors when loading individual files (default: false)
 * @returns {Promise<LoadedFile[]>} Array of loaded files (empty if using callback)
 * @throws {FunctionalError} When directory format is invalid
 */
export const loadedFilesListing = async (
  context: AuthContext,
  user: AuthUser,
  directory: string,
  opts: { recursive?: boolean; callback?: ((files: LoadedFile[]) => void) | null; dontThrow?: boolean } = {}
): Promise<LoadedFile[]> => {
  const { recursive = false, callback = null, dontThrow = false } = opts;
  const files: LoadedFile[] = [];
  if (isNotEmptyField(directory) && (directory as string).startsWith('/')) {
    throw FunctionalError('File listing directory must not start with a /');
  }
  if (isNotEmptyField(directory) && !(directory as string).endsWith('/')) {
    throw FunctionalError('File listing directory must end with a /');
  }
  let truncated = true;
  let continuationToken;
  while (truncated) {
    try {
      const response = await rawListObjects(directory, recursive ?? false, continuationToken);
      const resultFiles = filesAdaptation(response.Contents ?? []);
      const resultLoaded = await promiseMap(
        resultFiles,
        (f: S3FileObject) => loadFile(context, user, f.Key, { dontThrow }),
        5
      );
      if (callback) {
        callback(resultLoaded.filter((n) => n !== undefined));
      } else {
        files.push(...resultLoaded.filter((n) => n !== undefined));
      }
      truncated = response.IsTruncated ?? false;
      if (truncated) {
        continuationToken = response.NextContinuationToken;
      }
    } catch (err) {
      logApp.error('[FILE STORAGE] Storage files read fail', { cause: err });
      truncated = false;
    }
  }
  return files;
};

/**
 * Creates and schedules import jobs for a file using available connectors.
 * Filters connectors based on manual mode, connector ID, and contextual requirements.
 * Sends job messages to connector queues via RabbitMQ.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user initiating the import
 * @param {LoadedFile} file - The file to import
 * @param {string | null} entityId - Optional entity ID for contextual import
 * @param {Object} opts - Optional configuration
 * @param {boolean} opts.manual - Whether this is a manual import (default: false)
 * @param {string | null} opts.connectorId - Specific connector ID to use (default: null)
 * @param {string} opts.configuration - Custom connector configuration (default: null)
 * @param {boolean} opts.bypassValidation - Whether to bypass validation (default: false)
 * @param {string} opts.validationMode - Validation mode to use (default: defaultValidationMode)
 * @param {boolean} opts.forceValidation - Whether to force validation (default: false)
 * @returns {Promise<BasicStoreEntityConnector[]>} Array of connectors that received the import job
 */
export const uploadJobImport = async (
  context: AuthContext,
  user: AuthUser,
  file: LoadedFile,
  entityId: string | undefined,
  opts: {
    manual?: boolean;
    connectorId?: string | null;
    configuration?: string | null;
    bypassValidation?: boolean;
    validationMode?: string;
    forceValidation?: boolean;
  } = {}
): Promise<BasicStoreEntityConnector[]> => {
  const {
    manual = false,
    connectorId = null,
    configuration = null,
    bypassValidation = false,
    validationMode = defaultValidationMode,
    forceValidation = false
  } = opts;
  const draftContext = getDraftContext(context, user);
  let connectors = await connectorsForImport(context, user, file.metaData.mimetype ?? '', true, !manual);
  if (connectorId) {
    connectors = connectors.filter((n: BasicStoreEntityConnector) => n.id === connectorId);
  }
  if (!entityId) {
    connectors = connectors.filter((n: BasicStoreEntityConnector) => !n.only_contextual);
  }
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector: BasicStoreEntityConnector) => {
      const contextOutOfDraft = { ...context, draft_context: '' };
      const messageToUse = draftContext ? `Manual import of ${file.name} in draft ${draftContext}` : `Manual import of ${file.name}`;
      const work = await createWork(contextOutOfDraft, user, connector, messageToUse, file.id, { draftContext });
      return { connector, work };
    };
    const actionList = await Promise.all(connectors.map((connector: BasicStoreEntityConnector) => createConnectorWork(connector)));
    // Send message to all correct connectors queues
    const buildConnectorMessage = (data: { connector: BasicStoreEntityConnector; work: { id: string } }, connectorConfiguration: string | null) => {
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
          file_mime: file.metaData.mimetype ?? '',
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
    const pushMessage = (data: { connector: BasicStoreEntityConnector; work: { id: string } }) => {
      const { connector } = data;
      const message = buildConnectorMessage(data, configuration);
      return pushToConnector(connector.internal_id, message);
    };
    await Promise.all(actionList.map((data) => pushMessage(data)));
  }
  return connectors;
};

/**
 * Internal function that triggers import jobs for a file on specified context entities.
 * Performs confidence level checks before triggering each job.
 * If no entities are provided, triggers a global import.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user initiating the import
 * @param {LoadedFile} file - The file to import
 * @param {BasicStoreEntity[]} contextEntities - Array of entities to use as import context (default: [])
 * @returns {Promise<void>}
 */
const triggerJobImport = async (
  context: AuthContext,
  user: AuthUser,
  file: LoadedFile,
  contextEntities: BasicStoreEntity[] = []
): Promise<void> => {
  if (contextEntities.length === 0) {
    // global import
    await uploadJobImport(context, user, file, undefined);
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

/**
 * Uploads a file to storage with metadata, validation, and optional automatic import triggering.
 * Handles file versioning, draft context, marking validation, and duplicate detection.
 * Automatically triggers import jobs for files in import directories unless disabled.
 * @param {AuthContext} context - The authentication context
 * @param {AuthUser} user - The user uploading the file
 * @param {string} filePath - The storage path where the file should be uploaded
 * @param {FileUploadData} fileUpload - The file upload data containing stream and filename
 * @param {FileUploadOpts} opts - Upload options including entity context, metadata, and import settings
 * @returns {Promise<{upload: LoadedFile, untouched: boolean}>} Upload result with file info and untouched flag
 * @throws {FunctionalError} When marking validation fails or file already exists with errorOnExisting option
 * @note Please consider using file-storage-helper#uploadToStorage() instead.
 */
// Please consider using file-storage-helper#uploadToStorage() instead.
export const upload = async (
  context: AuthContext,
  user: AuthUser,
  filePath: string,
  fileUpload: FileUploadData,
  opts: FileUploadOpts
): Promise<{ upload: LoadedFile; untouched: boolean }> => {
  const { entity, meta = {}, noTriggerImport = false, errorOnExisting = false, file_markings = [], importContextEntities = [] } = opts;
  // Verify markings
  for (let index = 0; index < (file_markings ?? []).length; index += 1) {
    const markingId = file_markings[index];
    await validateMarking(context, user, markingId);
  }
  const metadata: FileMetadata = { ...meta };
  if (!metadata.version) {
    metadata.version = now();
  }
  const { createReadStream, filename } = await fileUpload;
  const encoding = '7bit';
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
    if (utcDate((currentFile.metaData as FileMetadata).version as string).isSameOrAfter(utcDate(metadata.version as string))) {
      return { upload: { ...currentFile, information: '', uploadStatus: 'complete' } as LoadedFile, untouched: true };
    }
    if (errorOnExisting) {
      throw FunctionalError('A file already exists with this name');
    }
  }

  const creatorId = (currentFile?.metaData as FileMetadata)?.creator_id ? (currentFile.metaData as FileMetadata).creator_id : user.id;

  // Upload the data
  const readStream = createReadStream();
  const fileMime = metadata.mimetype ?? guessMimeType(key);
  const fullMetadata: FileMetadata = {
    ...metadata,
    filename: encodeURIComponent(truncatedFileName),
    mimetype: fileMime,
    encoding,
    creator_id: creatorId as string,
    entity_id: (entity as BasicStoreEntity)?.internal_id,
  };
  await rawUpload(key, readStream);
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
      jobImportContextEntities.push(entity as BasicStoreEntity);
    }
    await triggerJobImport(context, user, file, jobImportContextEntities);
  }
  return { upload: file, untouched: false };
};

/**
 * Converts a readable stream to a string by accumulating all data chunks.
 * @param {Readable} stream - The readable stream to convert
 * @returns {Promise<string>} Promise resolving to the complete stream content as a string
 */
export const streamConverter = (stream: Readable): Promise<string> => {
  return new Promise((resolve) => {
    let data = '';
    stream.on('data', (chunk: Buffer | string) => {
      data += chunk.toString();
    });
    stream.on('end', () => resolve(data));
  });
};
export interface FileUploadOpts {
  entity?: BasicStoreBase, // entity on which the file is uploaded
  meta?: Record<string, any>,
  noTriggerImport?: boolean,
  errorOnExisting?: boolean,
  file_markings?: string[],
  importContextEntities?: BasicStoreEntity[], // entities used for import context
}

export interface FileUploadData {
  createReadStream: () => Readable,
  filename: string,
  mimeType?: string,
}

/**
 * Upload a file (as ReadStream) to S3 or equivalent storage.
 * @param context
 * @param user
 * @param filePath path in S3 storage, should contain only '/', do not use fs.join() to create path (no '\').
 * @param fileUpload
 * @param opts
 */
export const uploadToStorage = (context: AuthContext, user: AuthUser, filePath: string, fileUpload: FileUploadData, opts: FileUploadOpts) => {
  return upload(context, user, filePath, fileUpload, opts);
};

/**
 * Creates a stream to read a file on filesystem.
 * @param localFilePath full path to file, do not append filename
 * @param localFileName
 * @param s3FileName target name on s3, can be different from local filename.
 * @param mimeType
 */
export const fileToReadStream = (localFilePath: string, localFileName: string, s3FileName: string, mimeType: string) => {
  const fullPathFile = join(localFilePath, localFileName);
  const buffer = fs.readFileSync(fullPathFile);
  return { createReadStream: () => Readable.from(buffer), filename: s3FileName, mimetype: mimeType };
};

export const ALL_ROOT_FOLDERS = [SUPPORT_STORAGE_PATH, IMPORT_STORAGE_PATH, EXPORT_STORAGE_PATH, FROM_TEMPLATE_STORAGE_PATH];
export const ALL_MERGEABLE_FOLDERS = [IMPORT_STORAGE_PATH, EXPORT_STORAGE_PATH, FROM_TEMPLATE_STORAGE_PATH];
/**
 * Delete all files in storage that relates to an element.
 * @param context
 * @param user
 * @param element
 */
export const deleteAllObjectFiles = async (context: AuthContext, user: AuthUser, element: BasicStoreObject) => {
  logApp.debug(`[FILE STORAGE] deleting all storage files for ${element.internal_id}`);
  let ids = [];
  if (element.entity_type === ENTITY_TYPE_SUPPORT_PACKAGE) {
    const supportPath = `${SUPPORT_STORAGE_PATH}/${element.internal_id}`;
    const supportFiles = await allFilesForPaths(context, user, [supportPath]);
    ids = supportFiles.map((file) => file.id);
  } else {
    const importPath = `${IMPORT_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const importFilesPromise = allFilesForPaths(context, user, [importPath]);
    const importWorkPromise = deleteWorkForSource(importPath);

    const embeddedPath = `${EMBEDDED_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const embeddedFilesPromise = allFilesForPaths(context, user, [embeddedPath]);
    const embeddedWorkPromise = deleteWorkForSource(embeddedPath);

    const exportPath = `${EXPORT_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const exportFilesPromise = allFilesForPaths(context, user, [exportPath]);
    const exportWorkPromise = deleteWorkForSource(exportPath);

    const fromTemplatePath = `${FROM_TEMPLATE_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const fromTemplateFilesPromise = allFilesForPaths(context, user, [fromTemplatePath]);
    const fromTemplateWorkPromise = deleteWorkForSource(fromTemplatePath);

    const [importFiles, embeddedFiles, exportFiles, fromTemplateFiles, _, __, ___, ____] = await Promise.all([
      importFilesPromise,
      embeddedFilesPromise,
      exportFilesPromise,
      fromTemplateFilesPromise,
      importWorkPromise,
      embeddedWorkPromise,
      exportWorkPromise,
      fromTemplateWorkPromise,
    ]);
    ids = [...importFiles, ...embeddedFiles, ...exportFiles, ...fromTemplateFiles].map((file) => file.id);
  }
  logApp.debug('[FILE STORAGE] deleting all files with ids:', { ids });
  return deleteFiles(context, user, ids);
};

/**
 * Delete all files in storage that relates to a draft.
 * @param context
 * @param user
 * @param draftId
 */
export const deleteAllDraftFiles = async (context: AuthContext, user: AuthUser, draftId: string) => {
  logApp.debug(`[FILE STORAGE] deleting all storage files for draft ${draftId}`);
  const contextInDraft = { ...context, draft_context: draftId };
  const draftFiles = await allFilesForPaths(contextInDraft, user, [getDraftFilePrefix(draftId)]);
  const draftFilesIds = draftFiles.map((file) => file.id);
  logApp.debug('[FILE STORAGE] deleting all draft files with ids:', { draftFilesIds });
  return deleteRawFiles(context, user, draftFilesIds);
};

/**
 * For test cleanup purpose.
 * First remove all bucket content, then delete bucket. Unless specific configuration on S3 bucket, a bucket cannot be removed if not empty.
 * @param context
 * @param user
 */
export const deleteAllBucketContent = async (context: AuthContext, user: AuthUser) => {
  for (let i = 0; i < ALL_ROOT_FOLDERS.length; i += 1) {
    const folder = ALL_ROOT_FOLDERS[i];
    const allFiles = await loadedFilesListing(context, user, `${folder}/`, { recursive: true, dontThrow: true });
    const ids = [];
    for (let fileI = 0; fileI < allFiles.length; fileI += 1) {
      const currentFile = allFiles[fileI];
      logApp.info('[FILE STORAGE] preparing for delete', { currentFile });
      if (currentFile?.id) {
        ids.push(currentFile.id);
      }
    }
    logApp.info(`[FILE STORAGE] deleting ${ids.length} files in ${folder}/`);
    await deleteFiles(context, user, ids);
  }

  // Once all files are deleted, then bucket can be removed.
  // -- commented because not working --
  // await deleteBucket();
};

/**
 * Move all file from source entity to target entity and then cleanup directories on S3.
 * If a file with the same name exists both in source entity and target entity, the kept file is the one in target entity
 * @param context
 * @param user
 * @param sourceEntity
 * @param targetEntity
 */
export const moveAllFilesFromEntityToAnother = async (context: AuthContext, user: AuthUser, sourceEntity: BasicStoreBase, targetEntity: BasicStoreBase) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot merge all files in draft');
  }
  const updatedXOpenctiFiles: Array<{ id: string; name: string; version?: string; mime_type?: string; file_markings: string[] }> = [];
  for (let folderI = 0; folderI < ALL_MERGEABLE_FOLDERS.length; folderI += 1) {
    try {
      const sourcePath = `${ALL_MERGEABLE_FOLDERS[folderI]}/${sourceEntity.entity_type}/${sourceEntity.internal_id}`;
      const targetPath = `${ALL_MERGEABLE_FOLDERS[folderI]}/${targetEntity.entity_type}/${targetEntity.internal_id}`;
      const importFilesToMove = await allFilesForPaths(context, user, [sourcePath]);
      const targetFiles = await allFilesForPaths(context, user, [targetPath]);
      const targetFilesNames = targetFiles.map((f) => f.name);

      for (let fileI = 0; fileI < importFilesToMove.length; fileI += 1) {
        const sourceFileDocument = importFilesToMove[fileI];
        const sourceFileName = sourceFileDocument.name;
        if (!targetFilesNames.includes(sourceFileName)) { // move the file only if no files with this name already exist in target
          const sourceFileS3Id = `${sourcePath}/${sourceFileName}`;
          const targetFileS3Id = `${targetPath}/${sourceFileName}`;
          logApp.info(`[FILE STORAGE] Moving from ${sourceFileS3Id} to: ${targetFileS3Id}`);
          const copyProps = { sourceId: sourceFileS3Id, targetId: targetFileS3Id, sourceDocument: sourceFileDocument, targetEntityId: targetEntity.internal_id };
          const newFile = await copyFile(context, copyProps);
          if (newFile) {
            const newFileForEntity = storeFileConverter(user, newFile);
            updatedXOpenctiFiles.push(newFileForEntity);

            await deleteFile(context, user, sourceFileS3Id); // TODO to be removed ? This will be done by merge delete no ?
          }
        }
      }
    } catch (err) {
      logApp.error('[FILE STORAGE] Merge of files failed', { cause: err, user_id: user.id, sourceEntity, targetEntity, folder: ALL_MERGEABLE_FOLDERS[folderI] });
    }
  }

  return updatedXOpenctiFiles;
};
