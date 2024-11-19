import fs from 'node:fs';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { CsvMapperParsed } from '../modules/internal/csvMapper/csvMapper-types';
import { sanitized, validateCsvMapper } from '../modules/internal/csvMapper/csvMapper-utils';
import { BundleBuilder } from './bundle-creator';
import { handleRefEntities, mappingProcess } from './csv-mapper';
import { convertStoreToStix } from '../database/stix-converter';
import type { BasicStoreBase, StoreCommon } from '../types/store';
import { parseReadableToLines, parsingProcess } from './csv-parser';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { objects } from '../schema/stixRefRelationship';
import { isEmptyField } from '../database/utils';
import conf, { logApp } from '../config/conf';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StixBundle, StixObject } from '../types/stix-common';
import { pushToWorkerForConnector } from '../database/rabbitmq';

const inlineEntityTypes = [ENTITY_TYPE_EXTERNAL_REFERENCE];
const LOG_PREFIX = '[OPENCTI MODULE] CSV';
const CSV_MAX_BUNDLE_SIZE_GENERATION = conf.get('app:csv_ingestion:max_bundle_size') || 500;

// ----------------------------
// region CSV actual Ingestion

export interface CsvBundlerIngestionOpts {
  workId: string,
  applicantUser: AuthUser,
  entity: BasicStoreBase | undefined,
  csvMapper: CsvMapperParsed,
  maxRecordNumber?: number,
  connectorId: string,
}

const sendBundleToWorker = async (bundle: BundleBuilder, opts: CsvBundlerIngestionOpts) => {
  // Handle container
  if (opts.entity && isStixDomainObjectContainer(opts.entity.entity_type)) {
    const refs = bundle.ids();
    const stixEntity = { ...convertStoreToStix(opts.entity), [objects.stixName]: refs };
    bundle.addObject(stixEntity);
  }

  const bundleBuilt = bundle.build();
  const bundleContentAsString = Buffer.from(JSON.stringify(bundleBuilt), 'utf-8').toString('base64');

  logApp.info(`${LOG_PREFIX} push bundle to worker with ${bundleBuilt.objects.length} objects`);
  await pushToWorkerForConnector(opts.connectorId, {
    type: 'bundle',
    update: true,
    applicant_id: opts.applicantUser.id,
    work_id: opts.workId,
    content: bundleContentAsString,
  });
};

/**
 * Generate stix bundles and send them.
 * @param context
 * @param lines
 * @param opts
 */
export const generateAndSendBundleProcess = async (
  context: AuthContext,
  lines: string[],
  opts: CsvBundlerIngestionOpts
) => {
  logApp.info(`${LOG_PREFIX} generate and push bundles for a bulk of ${lines.length}.`);
  let bundleNew = new BundleBuilder();
  const { csvMapper, applicantUser } = opts;
  const rawRecords = await parsingProcess(lines, csvMapper.separator, csvMapper.skipLineChar);
  const records = opts.maxRecordNumber ? rawRecords.slice(0, opts.maxRecordNumber) : rawRecords;
  const refEntities = await handleRefEntities(context, applicantUser, csvMapper);
  let totalBundleSend = 0;
  let totalObjectSend = 0;
  if (records) {
    for (let rec = 0; rec < records.length; rec += 1) {
      const record = records[rec];
      const isEmptyLine = record.length === 1 && isEmptyField(record[0]);
      if (!isEmptyLine) {
        try {
          // Compute input by representation
          const inputs = await mappingProcess(context, applicantUser, csvMapper, record, refEntities);
          // Remove inline elements
          const withoutInlineInputs = inputs.filter((input) => !inlineEntityTypes.includes(input.entity_type as string));
          // Transform entity to stix
          const stixObjects = withoutInlineInputs.map((input) => {
            const stixObject = convertStoreToStix(input as unknown as StoreCommon);
            // FIXME do we need that ?
            // stixObject.extensions[STIX_EXT_OCTI].converter_csv = record.join(csvMapper.separator);
            return stixObject;
          });

          // Add to bundle or else send current bundle content and move to next bundle.
          if (bundleNew.canAddObjects(stixObjects) && bundleNew.objects.length < CSV_MAX_BUNDLE_SIZE_GENERATION) {
            bundleNew.addObjects(stixObjects);
          } else {
            await sendBundleToWorker(bundleNew, opts);
            totalBundleSend += 1;
            totalObjectSend += bundleNew.objects.length;
            bundleNew = new BundleBuilder();
          }
        } catch (e) {
          logApp.error(e);
        }
      }
    }
    if (bundleNew.objects.length > 0) {
      await sendBundleToWorker(bundleNew, opts);
      totalObjectSend += bundleNew.objects.length;
      totalBundleSend += 1;
    }
  }
  logApp.info(`${LOG_PREFIX} generate and push bundles for a bulk of ${lines.length} - DONE.`);
  return { bundleCount: totalBundleSend, objectCount: totalObjectSend };
};
// END region CSV actual Ingestion
// ----------------------------

// ------------------------
// region Test CSV Ingestion
export interface CsvBundlerTestOpts {
  applicantUser: AuthUser,
  csvMapper: CsvMapperParsed,
  maxRecordNumber?: number,
}

/**
 * With upsert feature.
 * @param context
 * @param lines
 * @param opts
 */
export const generateTestBundle = async (
  context: AuthContext,
  lines: string[],
  opts: CsvBundlerTestOpts
) => {
  const { maxRecordNumber, csvMapper, applicantUser } = opts;
  const allBundles: BundleBuilder[] = [];
  allBundles.push(new BundleBuilder());
  const rawRecords = await parsingProcess(lines, csvMapper.separator, csvMapper.skipLineChar);
  const records = maxRecordNumber ? rawRecords.slice(0, maxRecordNumber) : rawRecords;
  const refEntities = await handleRefEntities(context, applicantUser, csvMapper);
  if (records) {
    for (let rec = 0; rec < records.length; rec += 1) {
      const record = records[rec];
      const isEmptyLine = record.length === 1 && isEmptyField(record[0]);
      if (!isEmptyLine) {
        try {
          // Compute input by representation
          const inputs = await mappingProcess(context, applicantUser, csvMapper, record, refEntities);
          // Remove inline elements
          const withoutInlineInputs = inputs.filter((input) => !inlineEntityTypes.includes(input.entity_type as string));
          // Transform entity to stix
          const stixObjects = withoutInlineInputs.map((input) => {
            const stixObject = convertStoreToStix(input as unknown as StoreCommon);
            // FIXME is it needed ??
            // stixObject.extensions[STIX_EXT_OCTI].converter_csv = record.join(csvMapper.separator);
            return stixObject;
          });

          // Add to bundle
          let added: boolean = false;
          let bundleIndex = 0;
          while (!added && bundleIndex < allBundles.length) {
            if (allBundles[bundleIndex].canAddObjects(stixObjects)) {
              allBundles[0].addObjects(stixObjects);
              added = true;
            }
            bundleIndex += 1;
          }

          if (!added) {
            const nextBuilder = new BundleBuilder();
            nextBuilder.addObjects(stixObjects);
            allBundles.push(nextBuilder);
          }
        } catch (e) {
          logApp.error(e);
        }
      }
    }
  }
  // Build and return the result
  return allBundles;
};

/**
 * Helper to remove csv file header,
 * including when there is some comment before.
 * Only when the file is in one chunk (no stream).
 * @param csvLines
 * @param skipLineChar
 */
export const removeHeaderFromFullFile = (csvLines:string[], skipLineChar: string) => {
  if (skipLineChar && skipLineChar.length === 1) {
    let isACommentLine: boolean = true;
    while (isACommentLine) {
      const theLine = csvLines.shift();
      if (!theLine?.startsWith(skipLineChar)) {
        isACommentLine = false;
      }
    }
  } else {
    csvLines.shift();
  }
};

export const getCsvTestObjects = async (
  context: AuthContext,
  lines: string[],
  opts: CsvBundlerTestOpts
) => {
  const bundlesBuilder = await generateTestBundle(context, lines, opts);
  let allObjects: StixObject[] = [];
  for (let i = 0; i < bundlesBuilder.length; i += 1) {
    const bundle: StixBundle = bundlesBuilder[i].build();
    allObjects = allObjects.concat(bundle.objects);
  }
  return allObjects;
};

export const getTestBundleObjectsFromFile = async (
  context: AuthContext,
  user: AuthUser,
  filePath: string,
  mapper: CsvMapperParsed
) => {
  const csvLines = await parseReadableToLines(fs.createReadStream(filePath));
  if (mapper.has_header) {
    removeHeaderFromFullFile(csvLines, mapper.skipLineChar);
  }

  const bundlerTestOptions: CsvBundlerTestOpts = {
    applicantUser: user,
    csvMapper: mapper,
  };

  return getCsvTestObjects(context, csvLines, bundlerTestOptions);
};
// End region Test CSV Ingestion
// -----------------------------

// Deprecated region
export interface BundleProcessOpts {
  entity?: BasicStoreBase
  maxRecordNumber?: number,
}

/** @deprecated Will be removed when workbench are replaced by draft.
 * To be replaced by bundleAllowUpsertProcess */
export const bundleProcess = async (
  context: AuthContext,
  user: AuthUser,
  lines: string[],
  mapper: CsvMapperParsed,
  opts: BundleProcessOpts = {}
) => {
  const { entity, maxRecordNumber } = opts;
  await validateCsvMapper(context, user, mapper);
  const sanitizedMapper = sanitized(mapper);
  const bundleBuilder = new BundleBuilder();
  let skipLine = sanitizedMapper.has_header;
  const rawRecords = await parsingProcess(lines, mapper.separator, mapper.skipLineChar);
  const records = maxRecordNumber ? rawRecords.slice(0, maxRecordNumber) : rawRecords;
  const refEntities = await handleRefEntities(context, user, mapper);
  if (records) {
    await Promise.all((records.map(async (record: string[]) => {
      const isEmptyLine = record.length === 1 && isEmptyField(record[0]);
      // Handle header
      if (skipLine) {
        skipLine = false;
      } else if (!isEmptyLine) {
        try {
          // Compute input by representation
          const inputs = await mappingProcess(context, user, sanitizedMapper, record, refEntities);
          // Remove inline elements
          const withoutInlineInputs = inputs.filter((input) => !inlineEntityTypes.includes(input.entity_type as string));
          // Transform entity to stix
          const stixObjects = withoutInlineInputs.map((input) => {
            const stixObject = convertStoreToStix(input as unknown as StoreCommon);
            stixObject.extensions[STIX_EXT_OCTI].converter_csv = record.join(sanitizedMapper.separator);
            return stixObject;
          });
          // Add to bundle
          bundleBuilder.addObjects(stixObjects);
        } catch (e) {
          logApp.error(e);
        }
      }
    })));
  }
  // Handle container
  if (entity && isStixDomainObjectContainer(entity.entity_type)) {
    const refs = bundleBuilder.ids();
    const stixEntity = { ...convertStoreToStix(entity), [objects.stixName]: refs };
    bundleBuilder.addObject(stixEntity);
  }
  // Build and return the result
  return bundleBuilder.build();
};
