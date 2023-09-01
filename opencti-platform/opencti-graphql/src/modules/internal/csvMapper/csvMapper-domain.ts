import type { AuthContext, AuthUser } from '../../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityCsvMapper, ENTITY_TYPE_CSV_MAPPER, type StoreEntityCsvMapper } from './csvMapper-types';
import type { CsvMapperAddInput, EditInput, QueryCsvMappersArgs } from '../../../generated/graphql';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../../domain/internalObject';
import { bundleProcess } from '../../../parser/csv-bundler';
import { parseCsvMapper } from './csvMapper-utils';

// -- UTILS --

export const csvMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, content: string) => {
  const csvMapper = parseCsvMapper(JSON.parse(configuration));
  const bundle = await bundleProcess(context, user, Buffer.from(content), csvMapper);
  return bundle.objects;
};

// -- CRUD --

export const findById = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  const csvMapper = await storeLoadById<BasicStoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
  return parseCsvMapper(csvMapper);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryCsvMappersArgs) => {
  return listEntitiesPaginated<BasicStoreEntityCsvMapper>(context, user, [ENTITY_TYPE_CSV_MAPPER], opts);
};

export const createCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperInput: CsvMapperAddInput) => {
  return createInternalObject<StoreEntityCsvMapper>(context, user, csvMapperInput, ENTITY_TYPE_CSV_MAPPER).then((entity) => parseCsvMapper(entity));
};

export const fieldPatchCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string, input: EditInput[]) => {
  return editInternalObject<StoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER, input).then((entity) => parseCsvMapper(entity));
};

export const deleteCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return deleteInternalObject(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};
