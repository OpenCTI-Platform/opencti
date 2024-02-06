var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import axios from 'axios';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_INGESTION_CSV } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_CSV_MAPPER } from '../internal/csvMapper/csvMapper-types';
import { bundleProcess } from '../../parser/csv-bundler';
import { findById as findCsvMapperById } from '../internal/csvMapper/csvMapper-domain';
export const findById = (context, user, ingestionId) => {
    return storeLoadById(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV);
};
// findLastCSVIngestion
export const findAllPaginated = (context, user, opts = {}) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_INGESTION_CSV], opts);
});
export const findAllCsvIngestions = (context, user, opts = {}) => __awaiter(void 0, void 0, void 0, function* () {
    return listAllEntities(context, user, [ENTITY_TYPE_INGESTION_CSV], opts);
});
export const findCsvMapperForIngestionById = (context, user, csvMapperId) => {
    return storeLoadById(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};
export const addIngestionCsv = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element, isCreation } = yield createEntity(context, user, input, ENTITY_TYPE_INGESTION_CSV, { complete: true });
    if (isCreation) {
        yield publishUserAction({
            user,
            event_type: 'mutation',
            event_scope: 'create',
            event_access: 'administration',
            message: `creates csv ingestion \`${input.name}\``,
            context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_CSV, input }
        });
    }
    return element;
});
export const patchCsvIngestion = (context, user, id, patch) => __awaiter(void 0, void 0, void 0, function* () {
    const patched = yield patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_CSV, patch);
    return patched.element;
});
export const ingestionCsvEditField = (context, user, ingestionId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const { element } = yield updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV, input);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for csv ingestion \`${element.name}\``,
        context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input }
    });
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
});
export const deleteIngestionCsv = (context, user, ingestionId) => __awaiter(void 0, void 0, void 0, function* () {
    const deleted = yield deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `deletes csv ingestion \`${deleted.name}\``,
        context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input: deleted }
    });
    return ingestionId;
});
export const fetchCsvFromUrl = (url, csvMapperSkipLineChar) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield axios.get(url, { responseType: 'arraybuffer' });
    const dataExtract = response.data.toString().split('\n')
        .filter((line) => ((!!csvMapperSkipLineChar && !line.startsWith(csvMapperSkipLineChar))
        || (!csvMapperSkipLineChar && !!line)))
        .join('\n');
    return Buffer.from(dataExtract);
});
export const fetchCsvExtractFromUrl = (url, csvMapperSkipLineChar) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield axios.get(url, { responseType: 'arraybuffer' });
    const TEST_LIMIT = 50;
    const dataExtract = response.data.toString().split('\n')
        .filter((line) => ((!!csvMapperSkipLineChar && !line.startsWith(csvMapperSkipLineChar))
        || (!csvMapperSkipLineChar && !!line)))
        .slice(0, TEST_LIMIT)
        .join('\n');
    return Buffer.from(dataExtract);
});
export const testCsvIngestionMapping = (context, user, uri, csv_mapper_id) => __awaiter(void 0, void 0, void 0, function* () {
    const csvMapper = yield findCsvMapperById(context, user, csv_mapper_id);
    const csvBuffer = yield fetchCsvExtractFromUrl(uri, csvMapper.skipLineChar);
    const bundle = yield bundleProcess(context, user, csvBuffer, csvMapper);
    return {
        objects: JSON.stringify(bundle.objects, null, 2),
        nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
        nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
    };
});
