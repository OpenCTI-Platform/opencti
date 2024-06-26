import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { CsvMapperParsed } from '../modules/internal/csvMapper/csvMapper-types';
import { sanitized, validateCsvMapper } from '../modules/internal/csvMapper/csvMapper-utils';
import { BundleBuilder } from './bundle-creator';
import { handleRefEntities, mappingProcess } from './csv-mapper';
import { convertStoreToStix } from '../database/stix-converter';
import type { BasicStoreBase, StoreCommon } from '../types/store';
import { parsingProcess } from './csv-parser';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { objects } from '../schema/stixRefRelationship';
import { isEmptyField } from '../database/utils';
import { logApp } from '../config/conf';
import { UnknownError } from '../config/errors';
import { STIX_EXT_OCTI } from '../types/stix-extensions';

const inlineEntityTypes = [ENTITY_TYPE_EXTERNAL_REFERENCE];

interface BundleProcessOpts {
  entity?: BasicStoreBase
  maxRecordNumber?: number
}

export const bundleProcess = async (
  context: AuthContext,
  user: AuthUser,
  content: Buffer | string,
  mapper: CsvMapperParsed,
  opts: BundleProcessOpts = {}
) => {
  const { entity, maxRecordNumber } = opts;
  await validateCsvMapper(context, user, mapper);
  const sanitizedMapper = sanitized(mapper);
  const bundleBuilder = new BundleBuilder();
  let skipLine = sanitizedMapper.has_header;
  const rawRecords = await parsingProcess(content, mapper.separator, mapper.skipLineChar);
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
          logApp.error(UnknownError('Error CSV mapping record', { cause: e }));
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
