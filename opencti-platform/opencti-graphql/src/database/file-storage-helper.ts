import { Readable } from 'stream';
import { join } from 'node:path';
import fs from 'node:fs';
import { copyFile, deleteFile, deleteFiles, loadedFilesListing, storeFileConverter, upload } from './file-storage';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../types/store';
import { logApp } from '../config/conf';
import { allFilesForPaths } from '../modules/internal/document/document-domain';
import { deleteWorkForSource } from '../domain/work';
import { ENTITY_TYPE_SUPPORT_PACKAGE } from '../modules/support/support-types';

interface FileUploadOpts {
  entity?:BasicStoreBase | unknown, // entity on which the file is uploaded
  meta? : any,
  noTriggerImport?: boolean,
  errorOnExisting?: boolean,
  file_markings?: string[],
  importContextEntities?: BasicStoreEntity[], // entities used for import context
}

interface FileUploadData {
  createReadStream: () => Readable,
  filename: string,
  mimeType?: string,
}

interface S3File {
  id: string,
  name: string,
  size: number,
  information: string,
  lastModified: Date,
  lastModifiedSinceMin: Date,
  metaData: {
    entity_id?: string
    mimetype: string
    order?: number
    description?: string
    inCarousel?: boolean
    filename?: string
    file_markings?: string[]
    version?: string
  }
  uploadStatus: string,
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

export const SUPPORT_STORAGE_PATH = 'support';
export const IMPORT_STORAGE_PATH = 'import';
export const EXPORT_STORAGE_PATH = 'export';

export const ALL_ROOT_FOLDERS = [SUPPORT_STORAGE_PATH, IMPORT_STORAGE_PATH, EXPORT_STORAGE_PATH];
export const ALL_MERGEABLE_FOLDERS = [IMPORT_STORAGE_PATH, EXPORT_STORAGE_PATH];
/**
 * Delete all files in storage that relates to an element.
 * @param context
 * @param user
 * @param element
 */
export const deleteAllObjectFiles = async (context: AuthContext, user: AuthUser, element: any) => {
  logApp.info(`[FILE STORAGE] deleting all storage files for ${element.internal_id}`);

  let ids = [];
  if (element.entity_type === ENTITY_TYPE_SUPPORT_PACKAGE) {
    const supportPath = `${SUPPORT_STORAGE_PATH}/${element.internal_id}`;
    const supportFiles = await allFilesForPaths(context, user, [supportPath]);
    ids = supportFiles.map((file) => file.id);
  } else {
    const importPath = `${IMPORT_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const importFilesPromise = allFilesForPaths(context, user, [importPath]);
    const importWorkPromise = deleteWorkForSource(importPath);

    const exportPath = `${EXPORT_STORAGE_PATH}/${element.entity_type}/${element.internal_id}`;
    const exportFilesPromise = allFilesForPaths(context, user, [exportPath]);
    const exportWorkPromise = deleteWorkForSource(exportPath);

    const [importFiles, exportFiles, _, __] = await Promise.all([
      importFilesPromise,
      exportFilesPromise,
      importWorkPromise,
      exportWorkPromise
    ]);
    ids = [...importFiles, ...exportFiles].map((file) => file.id);
  }
  logApp.debug('[FILE STORAGE] deleting all files with ids:', { ids });
  return deleteFiles(context, user, ids);
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
    const allFiles = await loadedFilesListing(context, user, `${folder}/`, { recursive: true });
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
 * @param context
 * @param user
 * @param sourceEntity
 * @param targetEntity
 */
export const moveAllFilesFromEntityToAnother = async (context: AuthContext, user: AuthUser, sourceEntity: BasicStoreBase, targetEntity: BasicStoreBase) => {
  const updatedXOpenctiFiles: Partial<S3File> [] = [];

  for (let folderI = 0; folderI < ALL_MERGEABLE_FOLDERS.length; folderI += 1) {
    try {
      const sourcePath = `${ALL_MERGEABLE_FOLDERS[folderI]}/${sourceEntity.entity_type}/${sourceEntity.internal_id}`;
      const targetPath = `${ALL_MERGEABLE_FOLDERS[folderI]}/${targetEntity.entity_type}/${targetEntity.internal_id}`;
      const importFilesToMove = await allFilesForPaths(context, user, [sourcePath]);

      for (let fileI = 0; fileI < importFilesToMove.length; fileI += 1) {
        const sourceFileDocument = importFilesToMove[fileI];
        const sourceFileS3Id = `${sourcePath}/${sourceFileDocument.name}`;
        const targetFileS3Id = `${targetPath}/${sourceFileDocument.name}`;
        logApp.info(`[FILE STORAGE] Moving from ${sourceFileS3Id} to: ${targetFileS3Id}`);
        const newFile = await copyFile(sourceFileS3Id, targetFileS3Id, sourceFileDocument, targetEntity.internal_id);
        if (newFile) {
          const newFileForEntity = storeFileConverter(user, newFile);
          updatedXOpenctiFiles.push(newFileForEntity);

          await deleteFile(context, user, sourceFileS3Id); // TODO to be removed ? This will be done by merge delete no ?
        }
      }
    } catch (err) {
      logApp.error('[FILE STORAGE] Merge of files failed', { cause: err, user_id: user.id, sourceEntity, targetEntity, folder: ALL_MERGEABLE_FOLDERS[folderI] });
    }
  }

  return updatedXOpenctiFiles;
};
