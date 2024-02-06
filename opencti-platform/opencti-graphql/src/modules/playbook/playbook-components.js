var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import * as jsonpatch from 'fast-json-patch';
import { ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { AUTOMATION_MANAGER_USER, AUTOMATION_MANAGER_USER_UUID, executionContext, INTERNAL_USERS, isUserCanAccessStixElement, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToPlaybook } from '../../database/rabbitmq';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_RELATIONSHIP, ENTITY_TYPE_CONTAINER, INPUT_CREATED_BY, INPUT_LABELS, INPUT_MARKINGS, } from '../../schema/general';
import { convertStoreToStix } from '../../database/stix-converter';
import { generateInternalId, generateStandardId } from '../../schema/identifier';
import { now, observableValue, utcDate } from '../../utils/format';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_CONTAINER_REPORT, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-extensions';
import { connectorsForPlaybook } from '../../database/repository';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { listAllEntities, listAllRelations, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { createdBy, objectLabel, objectMarking } from '../../schema/stixRefRelationship';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { extractStixRepresentative } from '../../database/stix-representative';
import { isEmptyField, isNotEmptyField, READ_ENTITIES_INDICES_WITHOUT_INFERRED, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { stixLoadByIds } from '../../database/middleware';
import { usableNotifiers } from '../notifier/notifier-domain';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION } from '../../manager/notificationManager';
import { storeNotificationEvent } from '../../database/redis';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { createStixPattern } from '../../python/pythonBridge';
import { generateKeyValueForIndicator } from '../../domain/stixCyberObservable';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { extractObservablesFromIndicatorPattern, STIX_PATTERN_TYPE } from '../../utils/syntax';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
const extractBundleBaseElement = (instanceId, bundle) => {
    const baseData = bundle.objects.find((o) => o.id === instanceId);
    if (!baseData)
        throw FunctionalError('Playbook base element no longer accessible');
    return baseData;
};
const PLAYBOOK_LOGGER_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        level: {
            type: 'string',
            default: 'debug',
            $ref: 'Log level',
            oneOf: [
                { const: 'debug', title: 'debug' },
                { const: 'info', title: 'info' },
                { const: 'warning', title: 'warning' },
                { const: 'error', title: 'error' }
            ]
        },
    },
    required: ['level'],
};
const PLAYBOOK_LOGGER_COMPONENT = {
    id: 'PLAYBOOK_LOGGER_COMPONENT',
    name: 'Log data in standard output',
    description: 'Print bundle in platform logs',
    icon: 'console',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }],
    configuration_schema: PLAYBOOK_LOGGER_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_LOGGER_COMPONENT_SCHEMA; }),
    executor: ({ bundle, playbookNode }) => __awaiter(void 0, void 0, void 0, function* () {
        if (playbookNode.configuration.level) {
            logApp._log(playbookNode.configuration.level, '[PLAYBOOK MANAGER] Logger component output', { bundle });
        }
        return { output_port: 'out', bundle, forceBundleTracking: true };
    })
};
const PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA = {
    type: 'object',
    properties: {
        create: { type: 'boolean', default: true },
        update: { type: 'boolean', default: false },
        delete: { type: 'boolean', default: false },
        filters: { type: 'string' },
    },
    required: ['create', 'update', 'delete'],
};
const PLAYBOOK_INTERNAL_DATA_STREAM = {
    id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
    name: 'Listen knowledge events',
    description: 'Listen for all platform knowledge events',
    icon: 'stream',
    is_entry_point: true,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }],
    configuration_schema: PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA; }),
    executor: ({ bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        return ({ output_port: 'out', bundle, forceBundleTracking: true });
    })
};
const PLAYBOOK_INGESTION_COMPONENT = {
    id: 'PLAYBOOK_INGESTION_COMPONENT',
    name: 'Send for ingestion',
    description: 'Send STIX data for ingestion',
    icon: 'storage',
    is_entry_point: false,
    is_internal: true,
    ports: [],
    configuration_schema: undefined,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return undefined; }),
    executor: ({ bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
        yield pushToPlaybook({ type: 'bundle', applicant_id: AUTOMATION_MANAGER_USER_UUID, content, update: true });
        return { output_port: undefined, bundle, forceBundleTracking: true };
    })
};
const PLAYBOOK_FILTERING_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        all: { type: 'boolean', $ref: 'Filter on elements included in the bundle', default: false },
        filters: { type: 'string' },
    },
    required: ['filters'],
};
const PLAYBOOK_FILTERING_COMPONENT = {
    id: 'PLAYBOOK_FILTERING_COMPONENT',
    name: 'Filter knowledge',
    description: 'Filter STIX data',
    icon: 'filter',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }, { id: 'no-match', type: 'out' }],
    configuration_schema: PLAYBOOK_FILTERING_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_FILTERING_COMPONENT_SCHEMA; }),
    executor: ({ playbookNode, dataInstanceId, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const { filters, all } = playbookNode.configuration;
        const jsonFilters = JSON.parse(filters);
        // Checking on all bundle elements
        if (all) {
            let matchedElements = 0;
            for (let index = 0; index < bundle.objects.length; index += 1) {
                const bundleElement = bundle.objects[index];
                const isMatch = yield isStixMatchFilterGroup(context, SYSTEM_USER, bundleElement, jsonFilters);
                if (isMatch)
                    matchedElements += 1;
            }
            return { output_port: matchedElements > 0 ? 'out' : 'no-match', bundle };
        }
        // Only checking base data
        const baseData = extractBundleBaseElement(dataInstanceId, bundle);
        const isMatch = yield isStixMatchFilterGroup(context, SYSTEM_USER, baseData, jsonFilters);
        return { output_port: isMatch ? 'out' : 'no-match', bundle };
    })
};
const PLAYBOOK_REDUCING_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        filters: { type: 'string' },
    },
    required: ['filters'],
};
const PLAYBOOK_REDUCING_COMPONENT = {
    id: 'PLAYBOOK_REDUCING_COMPONENT',
    name: 'Reduce knowledge',
    description: 'Reduce STIX data according to the filter (keep only matching)',
    icon: 'reduce',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }],
    configuration_schema: PLAYBOOK_REDUCING_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_REDUCING_COMPONENT_SCHEMA; }),
    executor: ({ playbookNode, dataInstanceId, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const baseData = extractBundleBaseElement(dataInstanceId, bundle);
        const { filters } = playbookNode.configuration;
        const jsonFilters = JSON.parse(filters);
        const matchedElements = [baseData];
        for (let index = 0; index < bundle.objects.length; index += 1) {
            const bundleElement = bundle.objects[index];
            const isMatch = yield isStixMatchFilterGroup(context, SYSTEM_USER, bundleElement, jsonFilters);
            if (isMatch && baseData.id !== bundleElement.id)
                matchedElements.push(bundleElement);
        }
        const newBundle = Object.assign(Object.assign({}, bundle), { objects: matchedElements });
        return { output_port: 'out', bundle: newBundle };
    })
};
const PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        connector: { type: 'string', $ref: 'Enrichment connector', oneOf: [] },
    },
    required: ['connector'],
};
const PLAYBOOK_CONNECTOR_COMPONENT = {
    id: 'PLAYBOOK_CONNECTOR_COMPONENT',
    name: 'Enrich through connector',
    description: 'Use a registered platform connector for enrichment',
    icon: 'connector',
    is_entry_point: false,
    is_internal: false,
    ports: [{ id: 'out', type: 'out' }], // { id: 'unmodified', type: 'out' }]
    configuration_schema: PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const connectors = yield connectorsForPlaybook(context, SYSTEM_USER);
        const elements = connectors.map((c) => ({ const: c.id, title: c.name }))
            .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
        const schemaElement = { properties: { connector: { oneOf: elements } } };
        return R.mergeDeepRight(PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA, schemaElement);
    }),
    notify: ({ executionId, playbookId, playbookNode, previousPlaybookNode, dataInstanceId, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        if (playbookNode.configuration.connector) {
            const message = {
                internal: {
                    work_id: null, // No work id associated
                    playbook: {
                        execution_id: executionId,
                        playbook_id: playbookId,
                        data_instance_id: dataInstanceId,
                        step_id: playbookNode.id,
                        previous_step_id: previousPlaybookNode === null || previousPlaybookNode === void 0 ? void 0 : previousPlaybookNode.id,
                    },
                    applicant_id: AUTOMATION_MANAGER_USER.id, // System user is responsible for the automation
                },
                event: {
                    entity_id: dataInstanceId,
                    bundle
                },
            };
            yield pushToConnector(playbookNode.configuration.connector, message);
        }
    }),
    executor: ({ bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        // TODO Could be reactivated after improvement of enrichment connectors
        // if (previousStepBundle) {
        //   const diffOperations = jsonpatch.compare(previousStepBundle.objects, bundle.objects);
        //   if (diffOperations.length === 0) {
        //     return { output_port: 'unmodified', bundle };
        //   }
        // }
        return { output_port: 'out', bundle };
    })
};
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        container_type: { type: 'string', $ref: 'Container type', default: '', oneOf: [] },
        all: { type: 'boolean', $ref: 'Wrap all elements included in the bundle', default: false }
    },
    required: ['container_type'],
};
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT = {
    id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
    name: 'Container wrapper',
    description: 'Create a container and wrap the element inside it',
    icon: 'container',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }],
    configuration_schema: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () {
        const entityTypes = schemaTypesDefinition.get(ENTITY_TYPE_CONTAINER);
        const elements = entityTypes.map((c) => ({ const: c, title: c }));
        const schemaElement = { properties: { container_type: { oneOf: elements } } };
        return R.mergeDeepRight(PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA, schemaElement);
    }),
    executor: ({ dataInstanceId, playbookNode, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const { container_type, all } = playbookNode.configuration;
        if (container_type && isStixDomainObjectContainer(container_type)) {
            const baseData = extractBundleBaseElement(dataInstanceId, bundle);
            const created = baseData.extensions[STIX_EXT_OCTI].created_at;
            const containerData = {
                name: (_a = extractStixRepresentative(baseData)) !== null && _a !== void 0 ? _a : `Generated container wrapper from playbook at ${created}`,
                created,
                published: created,
            };
            const standardId = generateStandardId(container_type, containerData);
            const storeContainer = Object.assign({ internal_id: uuidv4(), standard_id: standardId, entity_type: container_type, parent_types: getParentTypes(container_type) }, containerData);
            const container = convertStoreToStix(storeContainer);
            if (all) {
                container.object_refs = bundle.objects.map((o) => o.id);
            }
            else {
                container.object_refs = [baseData.id];
            }
            // Specific remapping of some attributes, waiting for a complete binding solution in the UI
            if (baseData.object_marking_refs) {
                container.object_marking_refs = baseData.object_marking_refs;
            }
            if (baseData.labels) {
                container.labels = baseData.labels;
            }
            if (baseData.created_by_ref) {
                container.created_by_ref = baseData.created_by_ref;
            }
            if (baseData.severity && container_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
                container.severity = baseData.severity;
            }
            if (baseData.extensions[STIX_EXT_OCTI].participant_ids) {
                container.extensions[STIX_EXT_OCTI].participant_ids = baseData.extensions[STIX_EXT_OCTI].participant_ids;
            }
            if (baseData.extensions[STIX_EXT_OCTI].assignee_ids) {
                container.extensions[STIX_EXT_OCTI].assignee_ids = baseData.extensions[STIX_EXT_OCTI].assignee_ids;
            }
            bundle.objects.push(container);
        }
        return { output_port: 'out', bundle };
    })
};
const PLAYBOOK_SHARING_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        organizations: {
            type: 'array',
            uniqueItems: true,
            default: [],
            $ref: 'Target organizations',
            items: { type: 'string', oneOf: [] }
        },
        operation: {
            type: 'string',
            default: 'add',
            $ref: 'Operation to apply',
            oneOf: [
                { const: 'add', title: 'Add' },
                { const: 'remove', title: 'Remove' },
                { const: 'replace', title: 'Replace' }
            ]
        },
    },
    required: ['organizations', 'operation'],
};
const PLAYBOOK_SHARING_COMPONENT = {
    id: 'PLAYBOOK_SHARING_COMPONENT',
    name: 'Manage sharing with organizations',
    description: 'Share/Unshare with organizations within the platform',
    icon: 'identity',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }],
    configuration_schema: PLAYBOOK_SHARING_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const organizations = yield listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_ORGANIZATION], { connectionFormat: false, indices: READ_ENTITIES_INDICES_WITHOUT_INFERRED });
        const elements = organizations.map((c) => ({ const: c.id, title: c.name }));
        const schemaElement = { properties: { organizations: { items: { oneOf: elements } } } };
        return R.mergeDeepRight(PLAYBOOK_SHARING_COMPONENT_SCHEMA, schemaElement);
    }),
    executor: ({ dataInstanceId, playbookNode, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        var _b, _c;
        const context = executionContext('playbook_components');
        const allOrganizations = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
        const { organizations, operation } = playbookNode.configuration;
        const organizationIds = allOrganizations
            .filter((o) => (organizations !== null && organizations !== void 0 ? organizations : []).includes(o.internal_id))
            .map((o) => o.standard_id);
        const baseData = bundle.objects.find((o) => o.id === dataInstanceId);
        // granted_refs are always fully change on absorption level
        // We only need to compute the expected final result
        if (operation === UPDATE_OPERATION_ADD) {
            baseData.extensions[STIX_EXT_OCTI].granted_refs = [...((_b = baseData.extensions[STIX_EXT_OCTI].granted_refs) !== null && _b !== void 0 ? _b : []), ...organizationIds];
        }
        if (operation === UPDATE_OPERATION_REMOVE && organizationIds.length > 0) {
            // noinspection UnnecessaryLocalVariableJS
            const remainingOrganizations = ((_c = baseData.extensions[STIX_EXT_OCTI].granted_refs) !== null && _c !== void 0 ? _c : [])
                .filter((o) => organizationIds.some((select) => o !== select));
            baseData.extensions[STIX_EXT_OCTI].granted_refs = remainingOrganizations;
        }
        if (operation === UPDATE_OPERATION_REPLACE) {
            baseData.extensions[STIX_EXT_OCTI].granted_refs = organizationIds;
        }
        return { output_port: 'out', bundle };
    })
};
const attributePathMapping = {
    [INPUT_MARKINGS]: {
        [ABSTRACT_STIX_CORE_OBJECT]: `/${objectMarking.stixName}`,
        [ABSTRACT_STIX_RELATIONSHIP]: `/${objectMarking.stixName}`,
    },
    [INPUT_LABELS]: {
        [ABSTRACT_STIX_DOMAIN_OBJECT]: `/${objectLabel.stixName}`,
        [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/${objectLabel.stixName}`,
        [ABSTRACT_STIX_RELATIONSHIP]: `/${objectLabel.stixName}`,
    },
    [INPUT_CREATED_BY]: {
        [ABSTRACT_STIX_DOMAIN_OBJECT]: `/${createdBy.stixName}`,
        [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/${createdBy.stixName}`,
        [ABSTRACT_STIX_RELATIONSHIP]: `/${createdBy.stixName}`,
    },
    confidence: {
        [ABSTRACT_STIX_DOMAIN_OBJECT]: '/confidence',
        [ABSTRACT_STIX_RELATIONSHIP]: '/confidence',
    },
    x_opencti_score: {
        [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/score`,
        [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/score`,
    },
    x_opencti_detection: {
        [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/detection`,
    },
    x_opencti_workflow_id: {
        [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
        [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    }
};
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        actions: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    op: { type: 'string', enum: ['add', 'replace', 'remove'] },
                    attribute: { type: 'string' },
                    value: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                label: { type: 'string' },
                                value: { type: 'string' },
                                patch_value: { type: 'string' }
                            },
                            required: ['label', 'value', 'patch_value'],
                        }
                    },
                },
                required: ['op', 'attribute', 'value'],
            }
        },
        all: { type: 'boolean', $ref: 'Manipulate all elements included in the bundle', default: false },
    },
    required: ['actions'],
};
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT = {
    id: 'PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT',
    name: 'Manipulate knowledge',
    description: 'Manipulate STIX data',
    icon: 'edit',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
    configuration_schema: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA; }),
    executor: ({ dataInstanceId, playbookNode, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const { actions, all } = playbookNode.configuration;
        // Compute if the attribute is defined as multiple in schema definition
        const isAttributeMultiple = (entityType, attribute) => {
            const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
            if (baseAttribute)
                return baseAttribute.multiple;
            const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, attribute);
            if (relationRef)
                return relationRef.multiple;
            return undefined;
        };
        // Compute if attribute is defined as numeric
        const isAttributeNumeric = (entityType, attribute) => {
            const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
            if (baseAttribute)
                return baseAttribute.type === 'numeric';
            return false;
        };
        // Compute the access path for the attribute in the static matrix
        const computeAttributePath = (entityType, attribute) => {
            if (attributePathMapping[attribute]) {
                if (attributePathMapping[attribute][entityType]) {
                    return attributePathMapping[attribute][entityType];
                }
                const key = Object.keys(attributePathMapping[attribute]).filter((o) => getParentTypes(entityType).includes(o)).at(0);
                if (key) {
                    return attributePathMapping[attribute][key];
                }
            }
            return undefined;
        };
        const patchOperations = [];
        for (let index = 0; index < bundle.objects.length; index += 1) {
            const element = bundle.objects[index];
            if (all || element.id === dataInstanceId) {
                const { type } = element.extensions[STIX_EXT_OCTI];
                const elementOperations = actions
                    .map((action) => {
                    const attrPath = computeAttributePath(type, action.attribute);
                    const multiple = isAttributeMultiple(type, action.attribute);
                    const numeric = isAttributeNumeric(type, action.attribute);
                    return ({ action, multiple, numeric, attrPath, path: `/objects/${index}${attrPath}` });
                })
                    // Unrecognized attributes must be filtered
                    .filter(({ attrPath, multiple }) => isNotEmptyField(multiple) && isNotEmptyField(attrPath))
                    // Map actions to data patches
                    .map(({ action, path, multiple, numeric }) => {
                    var _a, _b;
                    return ({
                        op: action.op,
                        path,
                        // eslint-disable-next-line no-nested-ternary,max-len
                        value: multiple ? action.value.map((o) => (numeric ? Number(o.patch_value) : o.patch_value)) : numeric ? Number((_a = R.head(action.value)) === null || _a === void 0 ? void 0 : _a.patch_value) : (_b = R.head(action.value)) === null || _b === void 0 ? void 0 : _b.patch_value
                    });
                });
                // Enlist operations to execute
                patchOperations.push(...elementOperations);
            }
        }
        // Apply operations if needed
        if (patchOperations.length > 0) {
            jsonpatch.applyPatch(bundle, patchOperations);
            return { output_port: 'out', bundle };
        }
        return { output_port: 'unmodified', bundle };
    })
};
const DATE_SEEN_RULE = 'seen_dates';
const RESOLVE_CONTAINER = 'resolve_container';
const RESOLVE_NEIGHBORS = 'resolve_neighbors';
const RESOLVE_INDICATORS = 'resolve_indicators';
const RESOLVE_OBSERVABLES = 'resolve_observables';
const ENTITIES_DATE_SEEN_PREFIX = ['threat-actor--', 'campaign--', 'incident--', 'infrastructure--', 'malware--'];
const PLAYBOOK_RULE_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        rule: {
            type: 'string',
            $ref: 'Rule to apply',
            oneOf: [
                { const: DATE_SEEN_RULE, title: 'First/Last seen computing extension from report publication date' },
                { const: RESOLVE_INDICATORS, title: 'Resolve indicators based on observables (add in bundle)' },
                { const: RESOLVE_OBSERVABLES, title: 'Resolve observables an indicator is based on (add in bundle)' },
                { const: RESOLVE_CONTAINER, title: 'Resolve container references (add in bundle)' },
                { const: RESOLVE_NEIGHBORS, title: 'Resolve neighbors relations and entities (add in bundle)' },
            ]
        },
    },
    required: ['rule'],
};
const PLAYBOOK_RULE_COMPONENT = {
    id: 'PLAYBOOK_RULE_COMPONENT',
    name: 'Apply predefined rule',
    description: 'Execute advanced predefined computing',
    icon: 'memory',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
    configuration_schema: PLAYBOOK_RULE_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_RULE_COMPONENT_SCHEMA; }),
    executor: ({ dataInstanceId, playbookNode, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        var _d;
        const context = executionContext('playbook_components');
        const baseData = extractBundleBaseElement(dataInstanceId, bundle);
        const { id, type } = baseData.extensions[STIX_EXT_OCTI];
        const { rule } = playbookNode.configuration;
        if (rule === RESOLVE_INDICATORS) {
            // RESOLVE_INDICATORS is for now only triggered on observable creation / update
            if (isStixCyberObservable(type)) {
                // Observable <-- (based on) -- Indicator
                const relationOpts = { toId: id, fromTypes: [ENTITY_TYPE_INDICATOR], indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED };
                const basedOnRelations = yield listAllRelations(context, AUTOMATION_MANAGER_USER, RELATION_BASED_ON, relationOpts);
                const targetIds = R.uniq(basedOnRelations.map((relation) => relation.fromId));
                if (targetIds.length > 0) {
                    const indicators = yield stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds);
                    bundle.objects.push(...indicators);
                    return { output_port: 'out', bundle };
                }
            }
        }
        if (rule === RESOLVE_OBSERVABLES) {
            // RESOLVE_OBSERVABLES is for now only triggered on indicator creation / update
            if (type === ENTITY_TYPE_INDICATOR) {
                // Indicator (based on) --> Observable
                const relationOpts = { fromId: id, toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE], indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED };
                const basedOnRelations = yield listAllRelations(context, AUTOMATION_MANAGER_USER, RELATION_BASED_ON, relationOpts);
                const targetIds = R.uniq(basedOnRelations.map((relation) => relation.fromId));
                if (targetIds.length > 0) {
                    const observables = yield stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds);
                    bundle.objects.push(...observables);
                    return { output_port: 'out', bundle };
                }
            }
        }
        if (rule === DATE_SEEN_RULE) {
            // DATE_SEEN_RULE is only triggered on report creation / update
            if (type === ENTITY_TYPE_CONTAINER_REPORT) {
                // Handle first seen synchro for reports creation / modification
                const report = baseData;
                const publicationDate = utcDate(report.published);
                const targetIds = ((_d = report.object_refs) !== null && _d !== void 0 ? _d : [])
                    .filter((o) => ENTITIES_DATE_SEEN_PREFIX.some((prefix) => o.startsWith(prefix)));
                if (targetIds.length > 0) {
                    const elements = yield stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds);
                    const elementsToPatch = elements
                        .map((e) => {
                        // Check if seen dates will be impacted.
                        const isImpactedBefore = publicationDate.isBefore(e.first_seen ? utcDate(e.first_seen) : utcDate());
                        const isImpactedAfter = publicationDate.isAfter(e.last_seen ? utcDate(e.last_seen) : utcDate());
                        return { element: e, isImpactedBefore, isImpactedAfter };
                    })
                        .filter((data) => {
                        return data.isImpactedBefore || data.isImpactedAfter;
                    })
                        .map((data) => {
                        const first_seen = data.isImpactedBefore ? publicationDate.toISOString() : data.element.first_seen;
                        const last_seen = data.isImpactedAfter ? publicationDate.toISOString() : data.element.last_seen;
                        return Object.assign(Object.assign({}, data.element), { first_seen, last_seen });
                    });
                    if (elementsToPatch.length > 0) {
                        bundle.objects.push(...elementsToPatch);
                        return { output_port: 'out', bundle };
                    }
                }
            }
        }
        if (rule === RESOLVE_CONTAINER) {
            // DATE_SEEN_RULE is only triggered on report creation / update
            if (isStixDomainObjectContainer(type)) {
                // Handle first seen synchro for reports creation / modification
                const container = baseData;
                if (container.object_refs && container.object_refs.length > 0) {
                    const elements = yield stixLoadByIds(context, AUTOMATION_MANAGER_USER, container.object_refs);
                    if (elements.length > 0) {
                        bundle.objects.push(...elements);
                        return { output_port: 'out', bundle };
                    }
                }
            }
        }
        if (rule === RESOLVE_NEIGHBORS) {
            const relations = yield listAllRelations(context, AUTOMATION_MANAGER_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, { fromOrToId: id, baseData: true, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED });
            let idsToResolve = R.uniq([
                ...relations.map((r) => r.id),
                ...relations.map((r) => (id === r.fromId ? r.toId : r.fromId))
            ]);
            // In case of relation, we also resolve the from and to
            const baseDataRelation = baseData;
            if (baseDataRelation.source_ref && baseDataRelation.target_ref) {
                idsToResolve = R.uniq([...idsToResolve, baseDataRelation.source_ref, baseDataRelation.target_ref]);
            }
            const elements = yield stixLoadByIds(context, AUTOMATION_MANAGER_USER, idsToResolve);
            if (elements.length > 0) {
                bundle.objects.push(...elements);
                return { output_port: 'out', bundle };
            }
        }
        return { output_port: 'unmodified', bundle };
    })
};
const convertAuthorizedMemberToUsers = (authorized_members) => __awaiter(void 0, void 0, void 0, function* () {
    var _e;
    if (isEmptyField(authorized_members)) {
        return [];
    }
    const context = executionContext('playbook_components');
    const platformUsers = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    const triggerAuthorizedMembersIds = (_e = authorized_members === null || authorized_members === void 0 ? void 0 : authorized_members.map((member) => member.value)) !== null && _e !== void 0 ? _e : [];
    const usersFromGroups = platformUsers.filter((user) => user.groups.map((g) => g.internal_id)
        .some((id) => triggerAuthorizedMembersIds.includes(id)));
    const usersFromOrganizations = platformUsers.filter((user) => user.organizations.map((g) => g.internal_id)
        .some((id) => triggerAuthorizedMembersIds.includes(id)));
    const usersFromIds = platformUsers.filter((user) => triggerAuthorizedMembersIds.includes(user.id));
    const withoutInternalUsers = [...usersFromOrganizations, ...usersFromGroups, ...usersFromIds]
        .filter((u) => INTERNAL_USERS[u.id] === undefined);
    return R.uniqBy(R.prop('id'), withoutInternalUsers);
});
const PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        notifiers: {
            type: 'array',
            uniqueItems: true,
            default: [],
            $ref: 'Notifiers',
            items: { type: 'string', oneOf: [] }
        },
        authorized_members: { type: 'object' },
    },
    required: ['notifiers', 'authorized_members'],
};
const PLAYBOOK_NOTIFIER_COMPONENT = {
    id: 'PLAYBOOK_NOTIFIER_COMPONENT',
    name: 'Send to notifier',
    description: 'Send user notification',
    icon: 'notification',
    is_entry_point: false,
    is_internal: true,
    ports: [],
    configuration_schema: PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const notifiers = yield usableNotifiers(context, SYSTEM_USER);
        const elements = notifiers.map((c) => ({ const: c.id, title: c.name }));
        const schemaElement = { properties: { notifiers: { items: { oneOf: elements } } } };
        return R.mergeDeepRight(PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA, schemaElement);
    }),
    executor: ({ playbookId, playbookNode, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('playbook_components');
        const playbook = yield storeLoadById(context, SYSTEM_USER, playbookId, ENTITY_TYPE_PLAYBOOK);
        const { notifiers, authorized_members } = playbookNode.configuration;
        const targetUsers = yield convertAuthorizedMemberToUsers(authorized_members);
        const notificationsCall = [];
        for (let index = 0; index < targetUsers.length; index += 1) {
            const targetUser = targetUsers[index];
            const stixElements = bundle.objects.filter((o) => isUserCanAccessStixElement(context, targetUser, o));
            const notificationEvent = {
                version: EVENT_NOTIFICATION_VERSION,
                playbook_source: playbook.name,
                notification_id: playbookNode.id,
                target: convertToNotificationUser(targetUser, notifiers),
                type: 'digest',
                data: stixElements.map((stixObject) => ({
                    notification_id: playbookNode.id,
                    instance: stixObject,
                    type: 'create', // TODO Improve that with type event follow up
                    message: `\`${playbookNode.name}\``
                }))
            };
            notificationsCall.push(storeNotificationEvent(context, notificationEvent));
        }
        if (notificationsCall.length > 0) {
            yield Promise.all(notificationsCall);
        }
        return { output_port: undefined, bundle };
    })
};
const PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        all: { type: 'boolean', $ref: 'Create indicator from all observables in the bundle', default: false },
    },
    required: [],
};
const PLAYBOOK_CREATE_INDICATOR_COMPONENT = {
    id: 'PLAYBOOK_CREATE_INDICATOR_COMPONENT',
    name: 'Promote observable to indicator',
    description: 'Create an indicator based on an observable',
    icon: 'indicator',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
    configuration_schema: PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA; }),
    executor: ({ playbookNode, dataInstanceId, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        const { all } = playbookNode.configuration;
        const context = executionContext('playbook_components');
        const baseData = extractBundleBaseElement(dataInstanceId, bundle);
        const observables = [baseData];
        if (all) {
            observables.push(...bundle.objects);
        }
        for (let index = 0; index < observables.length; index += 1) {
            const observable = observables[index];
            let { type } = observable.extensions[STIX_EXT_OCTI];
            if (isStixCyberObservable(type)) {
                const indicatorName = observableValue(Object.assign(Object.assign({}, observable), { entity_type: type }));
                const { key, value } = generateKeyValueForIndicator(type, indicatorName, observable);
                if (key.includes('Artifact')) {
                    type = 'StixFile';
                }
                const pattern = yield createStixPattern(context, AUTOMATION_MANAGER_USER, key, value);
                const { score } = observable.extensions[STIX_EXT_OCTI_SCO];
                if (pattern) {
                    const indicatorData = {
                        name: indicatorName,
                        x_opencti_main_observable_type: type,
                        x_opencti_score: score,
                        pattern,
                        pattern_type: STIX_PATTERN_TYPE,
                        extensions: {
                            [STIX_EXT_OCTI]: {
                                main_observable_type: type,
                                score,
                            }
                        }
                    };
                    const indicatorStandardId = generateStandardId(ENTITY_TYPE_INDICATOR, indicatorData);
                    const storeIndicator = Object.assign({ internal_id: generateInternalId(), standard_id: indicatorStandardId, entity_type: ENTITY_TYPE_INDICATOR, parent_types: getParentTypes(ENTITY_TYPE_INDICATOR) }, indicatorData);
                    const indicator = convertStoreToStix(storeIndicator);
                    if (observable.object_marking_refs) {
                        indicator.object_marking_refs = observable.object_marking_refs;
                    }
                    if (observable.extensions[STIX_EXT_OCTI_SCO].labels) {
                        indicator.labels = observable.extensions[STIX_EXT_OCTI_SCO].labels;
                    }
                    if (observable.extensions[STIX_EXT_OCTI_SCO].created_by_ref) {
                        indicator.created_by_ref = observable.extensions[STIX_EXT_OCTI_SCO].created_by_ref;
                    }
                    if (observable.extensions[STIX_EXT_OCTI_SCO].external_references) {
                        indicator.external_references = observable.extensions[STIX_EXT_OCTI_SCO].external_references;
                    }
                    bundle.objects.push(indicator);
                    const relationship = {
                        id: `relationship--${generateInternalId()}`,
                        type: 'relationship',
                        source_ref: indicator.id,
                        target_ref: observable.id,
                        relationship_type: RELATION_BASED_ON,
                        created: now(),
                        modified: now()
                    };
                    bundle.objects.push(relationship);
                    return { output_port: 'out', bundle };
                }
            }
        }
        return { output_port: 'unmodified', bundle };
    })
};
const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA = {
    type: 'object',
    properties: {
        all: { type: 'boolean', $ref: 'Create observable from all indicators in the bundle', default: false },
    },
    required: [],
};
const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT = {
    id: 'PLAYBOOK_CREATE_OBSERVABLE_COMPONENT',
    name: 'Extract observables from indicator',
    description: 'Create observables based on an indicator',
    icon: 'observable',
    is_entry_point: false,
    is_internal: true,
    ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
    configuration_schema: PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA,
    schema: () => __awaiter(void 0, void 0, void 0, function* () { return PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA; }),
    executor: ({ playbookNode, dataInstanceId, bundle }) => __awaiter(void 0, void 0, void 0, function* () {
        var _f;
        const { all } = playbookNode.configuration;
        const baseData = extractBundleBaseElement(dataInstanceId, bundle);
        const indicators = [baseData];
        if (all) {
            indicators.push(...bundle.objects);
        }
        for (let indexIndicator = 0; indexIndicator < indicators.length; indexIndicator += 1) {
            const indicator = indicators[indexIndicator];
            if (indicator.type === 'indicator') {
                const observables = extractObservablesFromIndicatorPattern(indicator.pattern);
                for (let indexObservable = 0; indexObservable < observables.length; indexObservable += 1) {
                    const observable = observables[indexObservable];
                    const description = (_f = indicator.description) !== null && _f !== void 0 ? _f : `Simple observable of indicator {${indicator.name || indicator.pattern}}`;
                    const { score } = indicator.extensions[STIX_EXT_OCTI];
                    const observableData = Object.assign(Object.assign({}, R.dissoc('type', observable)), { x_opencti_score: score, x_opencti_description: description, extensions: {
                            [STIX_EXT_OCTI_SCO]: {
                                score,
                                description,
                            }
                        } });
                    const observableStandardId = generateStandardId(observable.type, observableData);
                    const storeObservable = Object.assign({ internal_id: generateInternalId(), standard_id: observableStandardId, entity_type: observable.type, parent_types: getParentTypes(observable.type) }, observableData);
                    const stixObservable = convertStoreToStix(storeObservable);
                    if (indicator.object_marking_refs) {
                        stixObservable.object_marking_refs = indicator.object_marking_refs;
                    }
                    if (indicator.created_by_ref) {
                        stixObservable.extensions[STIX_EXT_OCTI_SCO].created_by_ref = indicator.created_by_ref;
                    }
                    if (indicator.labels) {
                        stixObservable.extensions[STIX_EXT_OCTI_SCO].labels = indicator.labels;
                    }
                    if (indicator.external_references) {
                        stixObservable.extensions[STIX_EXT_OCTI_SCO].external_references = indicator.external_references;
                    }
                    bundle.objects.push(stixObservable);
                    const relationship = {
                        id: `relationship--${generateInternalId()}`,
                        type: 'relationship',
                        source_ref: indicator.id,
                        target_ref: stixObservable.id,
                        relationship_type: RELATION_BASED_ON,
                        created: now(),
                        modified: now()
                    };
                    bundle.objects.push(relationship);
                }
                return { output_port: 'out', bundle };
            }
        }
        return { output_port: 'unmodified', bundle };
    })
};
// endregion
export const PLAYBOOK_COMPONENTS = {
    [PLAYBOOK_INTERNAL_DATA_STREAM.id]: PLAYBOOK_INTERNAL_DATA_STREAM,
    [PLAYBOOK_LOGGER_COMPONENT.id]: PLAYBOOK_LOGGER_COMPONENT,
    [PLAYBOOK_INGESTION_COMPONENT.id]: PLAYBOOK_INGESTION_COMPONENT,
    [PLAYBOOK_FILTERING_COMPONENT.id]: PLAYBOOK_FILTERING_COMPONENT,
    [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
    [PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.id]: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT,
    [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
    [PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.id]: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT,
    [PLAYBOOK_SHARING_COMPONENT.id]: PLAYBOOK_SHARING_COMPONENT,
    [PLAYBOOK_RULE_COMPONENT.id]: PLAYBOOK_RULE_COMPONENT,
    [PLAYBOOK_NOTIFIER_COMPONENT.id]: PLAYBOOK_NOTIFIER_COMPONENT,
    [PLAYBOOK_CREATE_INDICATOR_COMPONENT.id]: PLAYBOOK_CREATE_INDICATOR_COMPONENT,
    [PLAYBOOK_REDUCING_COMPONENT.id]: PLAYBOOK_REDUCING_COMPONENT,
    [PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.id]: PLAYBOOK_CREATE_OBSERVABLE_COMPONENT,
};
