import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import { addIngestionCsv, deleteIngestionCsv, findAllPaginated, findById, findCsvMapperForIngestionById, ingestionCsvEditField, testCsvIngestionMapping } from './ingestion-csv-domain';
const creatorLoader = batchLoader(batchCreator);
const ingestionCsvResolvers = {
    Query: {
        ingestionCsv: (_, { id }, context) => findById(context, context.user, id),
        ingestionCsvs: (_, args, context) => findAllPaginated(context, context.user, args),
        test_mapper: (_, { uri, csv_mapper_id }, context) => testCsvIngestionMapping(context, context.user, uri, csv_mapper_id),
    },
    IngestionCsv: {
        user: (ingestionCsv, _, context) => creatorLoader.load(ingestionCsv.user_id, context, context.user),
        csvMapper: (ingestionCsv, _, context) => findCsvMapperForIngestionById(context, context.user, ingestionCsv.csv_mapper_id),
    },
    Mutation: {
        ingestionCsvAdd: (_, { input }, context) => {
            return addIngestionCsv(context, context.user, input);
        },
        ingestionCsvDelete: (_, { id }, context) => {
            return deleteIngestionCsv(context, context.user, id);
        },
        ingestionCsvFieldPatch: (_, { id, input }, context) => {
            return ingestionCsvEditField(context, context.user, id, input);
        },
    },
};
export default ingestionCsvResolvers;
