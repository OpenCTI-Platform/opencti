var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { sanitized, validate } from '../modules/internal/csvMapper/csvMapper-utils';
import { BundleBuilder } from './bundle-creator';
import { mappingProcess } from './csv-mapper';
import { convertStoreToStix } from '../database/stix-converter';
import { entityType } from '../schema/attribute-definition';
import { getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { validateInputCreation } from '../schema/schema-validator';
import { parsingProcess } from './csv-parser';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { objects } from '../schema/stixRefRelationship';
import { isEmptyField } from '../database/utils';
const validateInput = (context, user, inputs) => __awaiter(void 0, void 0, void 0, function* () {
    yield Promise.all(inputs.map((input) => __awaiter(void 0, void 0, void 0, function* () {
        const entity_type = input[entityType.name];
        const entitySetting = yield getEntitySettingFromCache(context, entity_type);
        if (entitySetting) {
            yield validateInputCreation(context, user, entity_type, input, entitySetting);
        }
    })));
});
const inlineEntityTypes = [ENTITY_TYPE_EXTERNAL_REFERENCE];
export const bundleProcess = (context, user, content, mapper, entity) => __awaiter(void 0, void 0, void 0, function* () {
    yield validate(context, user, mapper);
    const sanitizedMapper = sanitized(mapper);
    const bundleBuilder = new BundleBuilder();
    let skipLine = sanitizedMapper.has_header;
    let records = yield parsingProcess(content, mapper.separator);
    if (mapper.skipLineChar) {
        records = records.filter((record) => !record[0].startsWith(mapper.skipLineChar));
    }
    if (records) {
        yield Promise.all((records.map((record) => __awaiter(void 0, void 0, void 0, function* () {
            const isEmptyLine = record.length === 1 && isEmptyField(record[0]);
            // Handle header
            if (skipLine) {
                skipLine = false;
            }
            else if (!isEmptyLine) {
                // Compute input by representation
                const inputs = yield mappingProcess(context, user, sanitizedMapper, record);
                // Remove inline elements
                const withoutInlineInputs = inputs.filter((input) => !inlineEntityTypes.includes(input.entity_type));
                // Validate elements
                yield validateInput(context, user, withoutInlineInputs);
                // Transform entity to stix
                const stixObjects = withoutInlineInputs.map((input) => convertStoreToStix(input));
                // Add to bundle
                bundleBuilder.addObjects(stixObjects);
            }
        }))));
    }
    // Handle container
    if (entity && isStixDomainObjectContainer(entity.entity_type)) {
        const refs = bundleBuilder.ids();
        const stixEntity = Object.assign(Object.assign({}, convertStoreToStix(entity)), { [objects.stixName]: refs });
        bundleBuilder.addObject(stixEntity);
    }
    return bundleBuilder.build();
});
