import fs from 'node:fs';
import { join } from 'node:path';
import archiver from 'archiver';
import type { AuthContext, AuthUser } from '../../types/user';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { type BasicStoreEntitySupportPackage, ENTITY_TYPE_SUPPORT_PACKAGE, type StoreEntitySupportPackage, SUPPORT_BUS } from './support-types';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import {
  BUS_TOPICS,
  logApp,
  logSupport,
  NODE_INSTANCE_ID,
  SUPPORT_LOG_FILE_PREFIX,
  SUPPORT_LOG_RELATIVE_LOCAL_DIR,
  TELEMETRY_LOG_FILE_PREFIX,
  TELEMETRY_LOG_RELATIVE_LOCAL_DIR
} from '../../config/conf';
import { downloadFile, loadedFilesListing, streamConverter } from '../../database/file-storage';
import type { EditInput, QuerySupportPackagesArgs, SupportPackageAddInput, SupportPackageForceZipInput } from '../../generated/graphql';
import { EditOperation, PackageStatus } from '../../generated/graphql';
import { updateAttribute } from '../../database/middleware';
import { fileToReadStream, SUPPORT_STORAGE_PATH, uploadToStorage } from '../../database/file-storage-helper';
import { wait } from '../../database/utils';
import {
  lockResource,
  notify,
  redisCountInErrorNodes,
  redisCountInProgressNodes,
  redisDeleteSupportPackageNodeStatus,
  redisStoreSupportPackageNodeStatus
} from '../../database/redis';
import { FilesystemError, TYPE_LOCK_ERROR } from '../../config/errors';
import { getSettings } from '../../domain/settings';

const ZIP_TIMEOUT_MS = 15000; // Max time to archive all files
const ZIP_MIME_TYPE = 'application/zip';

// FIXME FOR TESTS PURPOSE only, should be true in production.
const cleanupFiles: boolean = true;

export const getS3UploadFolder = (entityId: string) => {
  // Be careful to NOT use join, on S3 we need a / and not an OS dependent separator.
  return `${SUPPORT_STORAGE_PATH}/${entityId}`;
};

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntitySupportPackage>(context, user, id, ENTITY_TYPE_SUPPORT_PACKAGE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QuerySupportPackagesArgs) => {
  return listEntitiesPaginated<BasicStoreEntitySupportPackage>(context, user, [ENTITY_TYPE_SUPPORT_PACKAGE], args);
};

export const deleteSupportPackage = async (context: AuthContext, user: AuthUser, supportPackageId: string) => {
  logApp.info(`[OPENCTI-MODULE] - DELETE support package ${supportPackageId}.`);
  await redisDeleteSupportPackageNodeStatus(supportPackageId);
  return deleteInternalObject(context, user, supportPackageId, ENTITY_TYPE_SUPPORT_PACKAGE);
};

/**
 * Find all files from a filename list with format support.*
 * @param files
 * @param prefix
 */
export const findAllSupportFiles = (files: string[], prefix: string): string[] => {
  if (files.length === 0) {
    return [];
  }
  const allSupportFiles: string[] = [];
  files.forEach((file) => {
    if (file.startsWith(prefix)) {
      allSupportFiles.push(file);
    }
  });
  return allSupportFiles;
};

const archiveFolderToZip = async (zipLocalFolder: string, zipFullpath: string) => {
  const archive = archiver('zip');
  const output = fs.createWriteStream(zipFullpath);

  let closed = false;
  output.on('error', (error) => {
    throw FilesystemError(error, { zipFullpath });
  });
  output.on('close', () => {
    closed = true;
  });

  archive.pipe(output);
  archive.directory(zipLocalFolder, false);
  archive.directory('subdir/', 'new-subdir');
  await archive.finalize();

  // Wait until zip is complete, or timeout.
  let initWaitingTime = ZIP_TIMEOUT_MS;
  while (!closed && initWaitingTime > 0) {
    await wait(500);
    initWaitingTime -= 500;
  }
};

/**
 * Send current node .support/support.log.* latest file to a target folder in S3
 * @param context
 * @param user
 * @param entity
 */
export const sendCurrentNodeSupportLogToS3 = async (context: AuthContext, user: AuthUser, entity: StoreEntitySupportPackage) => {
  logSupport.warn(`Generating support package on node ${NODE_INSTANCE_ID}`);
  logApp.info(`getLatestSupportLogFile - Looking inside ${SUPPORT_LOG_RELATIVE_LOCAL_DIR} !`);
  const supportFiles = findAllSupportFiles(fs.readdirSync(SUPPORT_LOG_RELATIVE_LOCAL_DIR), SUPPORT_LOG_FILE_PREFIX);
  const telemetryFiles = findAllSupportFiles(fs.readdirSync(TELEMETRY_LOG_RELATIVE_LOCAL_DIR), TELEMETRY_LOG_FILE_PREFIX);
  const uploadDir = getS3UploadFolder(entity.id);
  // Upload support files
  for (let i = 0; i < supportFiles.length; i += 1) {
    logApp.info(`sendSupportLogToS3 - I have a support file ${supportFiles[i]} to send to ${uploadDir}.`);
    const s3Filename = `${supportFiles[i]}-${NODE_INSTANCE_ID}.log`;
    const file = fileToReadStream(SUPPORT_LOG_RELATIVE_LOCAL_DIR, supportFiles[i], s3Filename, 'text/plain');
    await uploadToStorage(context, user, uploadDir, file, {});
  }
  // Upload telemetry files
  for (let i = 0; i < telemetryFiles.length; i += 1) {
    logApp.info(`sendTelemetryLogToS3 - I have a telemetry file ${telemetryFiles[i]} to send to ${uploadDir}.`);
    const s3Filename = `${telemetryFiles[i]}-${NODE_INSTANCE_ID}.log`;
    const file = fileToReadStream(TELEMETRY_LOG_RELATIVE_LOCAL_DIR, telemetryFiles[i], s3Filename, 'text/plain');
    await uploadToStorage(context, user, uploadDir, file, {});
  }
};

const downloadAllLogFiles = async (user: AuthUser, s3Directory: string, localDirectory: string) => {
  const allSupportFiles = await loadedFilesListing(user, s3Directory, {});
  logApp.info('All support files:', { allSupportFiles });
  for (let i = 0; i < allSupportFiles.length; i += 1) {
    const supportFile = allSupportFiles[i];
    logApp.info(`Found ${supportFile?.name}`);
    if (supportFile && supportFile.name.substring(supportFile.name.length - 4, supportFile.name.length) !== '.zip') {
      const newLocalFile = join(localDirectory, `${supportFile.name}`);
      fs.closeSync(fs.openSync(newLocalFile, 'w'));
      const stream = await downloadFile(supportFile.id);
      const data = await streamConverter(stream);
      fs.writeFileSync(newLocalFile, data, {});
      logApp.info(`OK - Writing ${supportFile?.name} in ${localDirectory}`);
    }
  }
};

const uploadArchivedSupportPackageToS3 = async (context: AuthContext, user: AuthUser, zipFullpath: string, zipFileName: string, entity: BasicStoreEntitySupportPackage) => {
  const entityUpdated = { ...entity };
  const zipPathAndName = join(zipFullpath, zipFileName);

  if (fs.existsSync(zipFullpath)) {
    logApp.debug('Zip exists on filesystem, all good.');
    const uploadDirectory = getS3UploadFolder(entity.id);
    logApp.info(`sendSupportLogToS3 - I have a support zip file ${zipPathAndName} to send to ${uploadDirectory}.`);
    const { upload } = await uploadToStorage(context, user, uploadDirectory, fileToReadStream(zipFullpath, zipFileName, zipFileName, ZIP_MIME_TYPE), {});
    entityUpdated.package_url = upload.id;
    logApp.info(`sendSupportLogToS3 - upload id: ${upload.id}`);
  } else {
    logApp.warn(`An issue occurs when trying to archive the support package ${zipPathAndName}`);
  }
  return entityUpdated;
};

/**
 * When all nodes have sent files to support folder, one node need to zip them all, upload zip to s3 and update the entity with path to zip.
 * Or this can be called by the "force zip" request also.
 * @param context
 * @param user
 * @param entity
 */
export const zipAllSupportFiles = async (context: AuthContext, user: AuthUser, entity: BasicStoreEntitySupportPackage) => {
  logApp.info(`[OPENCTI-MODULE] creating zip on node ${NODE_INSTANCE_ID}`);
  const zipLocalRootFolder = join(SUPPORT_LOG_RELATIVE_LOCAL_DIR, entity.id);
  const zipLocalFullFolder: string = join(zipLocalRootFolder, NODE_INSTANCE_ID);

  if (!fs.existsSync(zipLocalFullFolder)) {
    fs.mkdirSync(zipLocalFullFolder, { recursive: true });
  }

  await downloadAllLogFiles(user, `${entity.package_upload_dir}/`, zipLocalFullFolder);

  const zipName = `${entity.id}.zip`;
  const zipFullpath = join(SUPPORT_LOG_RELATIVE_LOCAL_DIR, zipName);
  // FIXME I'm quite sure that we can generate a zip steam without writing on filesystem.
  await archiveFolderToZip(zipLocalFullFolder, zipFullpath);

  const updatedEntity2 = await uploadArchivedSupportPackageToS3(context, user, SUPPORT_LOG_RELATIVE_LOCAL_DIR, zipName, entity);

  // Cleaning zip folder and zip file locally
  if (cleanupFiles) {
    if (fs.existsSync(zipLocalRootFolder)) {
      fs.rmSync(zipLocalRootFolder, { recursive: true, force: true });
    }

    if (fs.existsSync(zipFullpath)) {
      fs.rmSync(zipFullpath, { recursive: true, force: true });
    }
  }

  const updateInput = [
    { key: 'package_url', value: [updatedEntity2.package_url], operation: EditOperation.Replace }
  ];
  await updateAttribute(context, user, entity.id, ENTITY_TYPE_SUPPORT_PACKAGE, updateInput);
};

/**
 * Prepare support package data: creates elastic entity and compute the S3 target folder.
 * @param context
 * @param user
 * @param input
 */
export const prepareNewSupportPackage = async (context: AuthContext, user: AuthUser, input: SupportPackageAddInput) => {
  const settings = await getSettings(context);
  logApp.info(`Starting support package generation with ${settings.platform_cluster.instances_number} nodes.`);
  const instancesNumber = settings.platform_cluster.instances_number;

  const defaultOps = {
    package_status: PackageStatus.InProgress,
    created_at: new Date(),
    nodes_count: instancesNumber,
  };
  const supportInput = { ...input, ...defaultOps };
  const supportDataCreated = await createInternalObject<StoreEntitySupportPackage>(context, user, supportInput, ENTITY_TYPE_SUPPORT_PACKAGE);

  const updateInput: EditInput[] = [{
    key: 'package_upload_dir',
    value: [getS3UploadFolder(supportDataCreated.id)],
    operation: EditOperation.Replace
  }];
  await updateAttribute(context, user, supportDataCreated.id, ENTITY_TYPE_SUPPORT_PACKAGE, updateInput);
  return supportDataCreated;
};

/**
 * Create the support package data in elastic, and send notification to all nodes (via pub/sub) to trigger support files upload to S3 from all nodes.
 * @param context
 * @param user
 * @param input
 */
export const addSupportPackage = async (context: AuthContext, user: AuthUser, input: SupportPackageAddInput) => {
  // Using  logSupport.warn on purpose to have the package date and time generation in support logs
  logSupport.warn(`Support Package ${input.name} requested`);
  const supportDataCreated = await prepareNewSupportPackage(context, user, input);

  // for listener see supportPackageListener
  await notify(BUS_TOPICS[SUPPORT_BUS].EDIT_TOPIC, supportDataCreated, user);
  return findById(context, user, supportDataCreated.id);
};

/**
 * Whatever all support files from all nodes are ready or not, we zip what we have.
 * @param context
 * @param user
 * @param supportPackage
 */
export const requestZipPackage = async (context: AuthContext, user: AuthUser, supportPackage: SupportPackageForceZipInput) => {
  const packageEntity = await findById(context, user, supportPackage.id);
  await zipAllSupportFiles(context, user, packageEntity);
  return findById(context, user, supportPackage.id);
};

/**
 * Register the current node status on sending logs for support package.
 * @param context
 * @param user
 * @param packageId
 * @param newStatus
 */
export const registerNodeInSupportPackage = async (context: AuthContext, user: AuthUser, packageId: string, newStatus: PackageStatus) => {
  logApp.info(`[OPENCTI-MODULE] Updating Support Package ${packageId} on node ${NODE_INSTANCE_ID} with status ${newStatus}`);
  const actualPackage = await findById(context, user, packageId);
  if (actualPackage) {
    let redisScore;
    switch (newStatus) {
      case
        PackageStatus.InError:
        redisScore = 100;
        break;
      case
        PackageStatus.Ready:
        redisScore = 10;
        break;
      default:
        redisScore = 0;
    }

    await redisStoreSupportPackageNodeStatus(actualPackage.id, NODE_INSTANCE_ID, redisScore);

    if (newStatus === PackageStatus.Ready || newStatus === PackageStatus.InError) {
      const inProgressNodes = await redisCountInProgressNodes(actualPackage.id);
      if (inProgressNodes === 0) {
        const lockId = `support-zip-lock:${packageId}:${NODE_INSTANCE_ID}`;
        let lock; // We don't want zip to be generated by 2 nodes in parallel.
        try {
          lock = await lockResource([lockId], { retryCount: 0 });

          await zipAllSupportFiles(context, user, actualPackage);

          const nodeInErrorCount = await redisCountInErrorNodes(actualPackage.id);
          if (nodeInErrorCount > 0) {
            const updateInput: EditInput[] = [{
              key: 'package_status',
              value: [PackageStatus.InError],
              operation: EditOperation.Replace
            }];
            await updateAttribute(context, user, packageId, ENTITY_TYPE_SUPPORT_PACKAGE, updateInput);
          } else {
            const updateInput: EditInput[] = [{
              key: 'package_status',
              value: [PackageStatus.Ready],
              operation: EditOperation.Replace
            }];
            await updateAttribute(context, user, packageId, ENTITY_TYPE_SUPPORT_PACKAGE, updateInput);
          }
        } catch (e: any) {
          if (e.name === TYPE_LOCK_ERROR) {
            logApp.debug('[OPENCTI-MODULE] Support package already started by another node');
          } else {
            logApp.error(e);
          }
        } finally {
          if (lock) await lock.unlock();
        }
      }
    }
  }
};
