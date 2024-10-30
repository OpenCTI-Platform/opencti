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
import { logApp } from '../config/conf';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StixBundle, StixObject } from '../types/stix-common';

const inlineEntityTypes = [ENTITY_TYPE_EXTERNAL_REFERENCE];

interface BundleProcessOpts {
  entity?: BasicStoreBase
  maxRecordNumber?: number
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

/**
 * Generate stix bundles. Try to put as much data as possible in the first bundle.
 * Creates a new bundle when a data already exists with the same stixId but the content is different from previously
 *  to allow upsert inside a same CSV file.
 * @param context
 * @param user
 * @param lines
 * @param mapper
 * @param opts
 */
export const bundleAllowUpsertProcess = async (
  context: AuthContext,
  user: AuthUser,
  lines: string[],
  mapper: CsvMapperParsed,
  opts: BundleProcessOpts = {}
) => {
  const { entity, maxRecordNumber } = opts;
  const allBundles: BundleBuilder[] = [];
  allBundles.push(new BundleBuilder());
  const rawRecords = await parsingProcess(lines, mapper.separator, mapper.skipLineChar);
  const records = maxRecordNumber ? rawRecords.slice(0, maxRecordNumber) : rawRecords;
  const refEntities = await handleRefEntities(context, user, mapper);
  if (records) {
    await Promise.all((records.map(async (record: string[]) => {
      const isEmptyLine = record.length === 1 && isEmptyField(record[0]);
      if (!isEmptyLine) {
        try {
          // Compute input by representation
          const inputs = await mappingProcess(context, user, mapper, record, refEntities);
          // Remove inline elements
          const withoutInlineInputs = inputs.filter((input) => !inlineEntityTypes.includes(input.entity_type as string));
          // Transform entity to stix
          const stixObjects = withoutInlineInputs.map((input) => {
            const stixObject = convertStoreToStix(input as unknown as StoreCommon);
            stixObject.extensions[STIX_EXT_OCTI].converter_csv = record.join(mapper.separator);
            return stixObject;
          });
          // Add to bundle
          let added: boolean = false;
          let i = 0;
          while (!added && i < allBundles.length) {
            if (allBundles[i].canAddObjects(stixObjects)) {
              allBundles[0].addObjects(stixObjects);
              added = true;
            }
            i += 1;
          }

          if (!added) {
            // console.log('Not added, add a new bundle');
            const nextBuilder = new BundleBuilder();
            nextBuilder.addObjects(stixObjects);
            allBundles.push(nextBuilder);
          }
        } catch (e) {
          logApp.error(e);
        }
      }
    })));
  }
  // Handle container
  if (entity && isStixDomainObjectContainer(entity.entity_type)) {
    for (let i = 0; i < allBundles.length; i += 1) {
      const currentBundle = allBundles[i];
      const refs = currentBundle.ids();
      const stixEntity = { ...convertStoreToStix(entity), [objects.stixName]: refs };
      currentBundle.addObject(stixEntity);
    }
  }
  // Build and return the result
  return allBundles;
};

export const bundleObjects = async (
  context: AuthContext,
  user: AuthUser,
  lines: string[],
  mapper: CsvMapperParsed,
  opts: BundleProcessOpts = {}
) => {
  const bundlesBuilder = await bundleAllowUpsertProcess(context, user, lines, mapper, opts);
  const allObjects: StixObject[] = [];
  for (let i = 0; i < bundlesBuilder.length; i += 1) {
    const bundle: StixBundle = bundlesBuilder[i].build();
    allObjects.push(...bundle.objects);
  }
  return allObjects;
};

export const bundleProcessFromFile = async (
  context: AuthContext,
  user: AuthUser,
  filePath: string,
  mapper: CsvMapperParsed
) => {
  const csvLines = await parseReadableToLines(fs.createReadStream(filePath));
  return bundleObjects(context, user, csvLines, mapper, {});
};
