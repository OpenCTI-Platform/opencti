var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import { FunctionalError } from '../../config/errors';
import { storeLoadByIdsWithRefs } from '../../database/middleware';
import { buildStixBundle, convertStoreToStix } from '../../database/stix-converter';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { generateStandardId } from '../../schema/identifier';
import { internalLoadById } from '../../database/middleware-loader';
import { addWorkspace } from './workspace-domain';
import { nowTime } from '../../utils/format';
import { READ_STIX_INDICES } from '../../database/utils';
import { getParentTypes } from '../../schema/schemaUtils';
import { filterUnwantedEntitiesOut } from '../../domain/container';
const buildStixReportForExport = (workspace, investigatedEntities) => {
    const id = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, { name: workspace.name, published: workspace.created_at });
    const report = {
        internal_id: uuidv4(),
        standard_id: id,
        name: workspace.name,
        published: workspace.created_at,
        entity_type: ENTITY_TYPE_CONTAINER_REPORT,
        parent_types: getParentTypes(ENTITY_TYPE_CONTAINER_REPORT),
        objects: investigatedEntities,
    };
    return convertStoreToStix(report);
};
export const toStixReportBundle = (context, user, workspace) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    if (workspace.type !== 'investigation') {
        throw FunctionalError('You can only export investigation objects as a stix report bundle.');
    }
    const investigatedEntitiesIds = (_a = workspace.investigated_entities_ids) !== null && _a !== void 0 ? _a : [];
    const storeInvestigatedEntities = yield storeLoadByIdsWithRefs(context, user, investigatedEntitiesIds, { indices: READ_STIX_INDICES });
    const stixReportForExport = buildStixReportForExport(workspace, storeInvestigatedEntities);
    const bundle = buildStixBundle([stixReportForExport, ...storeInvestigatedEntities.map((s) => convertStoreToStix(s))]);
    return JSON.stringify(bundle);
});
export const investigationAddFromContainer = (context, user, containerId) => __awaiter(void 0, void 0, void 0, function* () {
    const container = yield internalLoadById(context, user, containerId);
    const investigationToStartCanonicalName = `[${container.entity_type}] "${container.name}" (${nowTime()})`;
    const filteredOutInvestigatedIds = yield filterUnwantedEntitiesOut({ context, user, ids: container.object });
    const investigationInput = { type: 'investigation', name: investigationToStartCanonicalName, investigated_entities_ids: filteredOutInvestigatedIds };
    return addWorkspace(context, user, investigationInput);
});
