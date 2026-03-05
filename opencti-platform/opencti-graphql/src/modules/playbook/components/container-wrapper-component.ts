import type { JSONSchemaType } from 'ajv';
import { type PlaybookComponent } from '../playbook-types';
import { ENTITY_TYPE_CONTAINER_REPORT, STIX_DOMAIN_OBJECT_CONTAINER_CASES } from '../../../schema/stixDomainObject';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../case/feedback/feedback-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../../case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, type StixCaseIncident } from '../../case/case-incident/case-incident-types';
import { FunctionalError } from '../../../config/errors';
import { ENTITY_TYPE_CONTAINER_TASK } from '../../task/task-types';
import { extractBundleBaseElement } from '../playbook-utils';
import { now } from '../../../utils/format';
import { extractStixRepresentative } from '../../../database/stix-representative';
import { generateStandardId } from '../../../schema/identifier';
import * as R from 'ramda';
import { getParentTypes } from '../../../schema/schemaUtils';
import type { StoreCommon } from '../../../types/store';
import { convertStoreToStix_2_1 } from '../../../database/stix-2-1-converter';
import type { StixContainer, StixIncident, StixReport } from '../../../types/stix-2-1-sdo';
import type { StixDomainObject, StixObject } from '../../../types/stix-2-1-common';
import { createTaskFromCaseTemplates } from '../playbook-components';
import { pushAll } from '../../../utils/arrayUtil';
import { getFileContent } from '../../../database/raw-file-storage';
import { logApp } from '../../../config/conf';

// For now, only a fixed list of containers are compatible
// these are the containers that can be created with a name and no specific mandatory fields
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS = [
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_TASK,
];

export interface ContainerWrapperConfiguration {
  container_type: string;
  caseTemplates: { label: string; value: string }[];
  all: boolean;
  excludeMainElement: boolean;
  copyFiles: boolean;
  newContainer: boolean;
}

export const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA: JSONSchemaType<ContainerWrapperConfiguration> = {
  type: 'object',
  properties: {
    container_type: { type: 'string', $ref: 'Container type', default: '', oneOf: [] },
    caseTemplates: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Case templates',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Wrap all elements included in the bundle', default: false },
    excludeMainElement: { type: 'boolean', $ref: 'Exclude main element from container', default: false },
    copyFiles: { type: 'boolean', $ref: 'Copy files from main element to the container', default: false },
    newContainer: { type: 'boolean', $ref: 'Create a new container at each run', default: false },
  },
  required: ['container_type'],
};

export const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT: PlaybookComponent<ContainerWrapperConfiguration> = {
  id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
  name: 'Container wrapper',
  description: 'Create a container and wrap the element inside it',
  icon: 'container',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA,
  schema: async () => {
    const elements = PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS.map((t) => ({ const: t, title: t }));
    const schemaElement = { properties: { container_type: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<ContainerWrapperConfiguration>, any>(PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const { container_type, all, excludeMainElement, copyFiles, newContainer, caseTemplates } = playbookNode.configuration;
    if (!PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS.includes(container_type)) {
      throw FunctionalError('this container type is incompatible with the Container Wrapper playbook component', { container_type });
    }
    if (container_type) {
      const baseData = extractBundleBaseElement(dataInstanceId, bundle);
      const created = newContainer ? now() : baseData.extensions[STIX_EXT_OCTI].created_at;
      const representative = extractStixRepresentative(baseData);
      let name = `Generated container wrapper from playbook at ${created}`;
      if (representative && newContainer) {
        name = `${representative} - ${created}`;
      } else if (representative) {
        name = representative;
      }
      const containerData: Record<string, unknown> = {
        name,
        created,
      };
      if (container_type === ENTITY_TYPE_CONTAINER_REPORT) {
        containerData.published = created;
      }
      if (container_type === ENTITY_TYPE_CONTAINER_GROUPING) {
        containerData.context = 'playbook';
      }
      const standardId = generateStandardId(container_type, containerData);
      const storeContainer = {
        standard_id: standardId,
        entity_type: container_type,
        parent_types: getParentTypes(container_type),
        ...containerData,
      } as StoreCommon;
      const container = convertStoreToStix_2_1(storeContainer) as StixReport | StixCaseIncident;
      // add all objects in the container if requested in the playbook config
      if (all) {
        // If excludeMainElement is true and all is true, exclude the main element from the container
        if (excludeMainElement) {
          container.object_refs = bundle.objects.filter((o: StixObject) => o.id !== baseData.id).map((o: StixObject) => o.id);
        } else {
          container.object_refs = bundle.objects.map((o: StixObject) => o.id);
        }
      } else {
        container.object_refs = [baseData.id];
      }
      // Specific remapping of some attributes, waiting for a complete binding solution in the UI
      // Following attributes are the same as the base instance: description, content, markings, labels, created_by, assignees, participants
      if ((baseData as StixReport).description) {
        container.description = (baseData as StixReport).description;
      }
      if ((baseData as StixReport).extensions[STIX_EXT_OCTI].content) {
        (container as StixReport).extensions[STIX_EXT_OCTI].content = (baseData as StixReport).extensions[STIX_EXT_OCTI].content;
      }
      if ((baseData as StixCaseIncident).content) {
        (container as StixCaseIncident).content = (baseData as StixCaseIncident).content;
      }
      if (baseData.object_marking_refs) {
        container.object_marking_refs = baseData.object_marking_refs;
      }
      if ((<StixDomainObject>baseData).labels) {
        container.labels = (<StixDomainObject>baseData).labels;
      }
      if ((<StixDomainObject>baseData).created_by_ref) {
        container.created_by_ref = (<StixDomainObject>baseData).created_by_ref;
      }
      if (baseData.extensions[STIX_EXT_OCTI].participant_ids) {
        container.extensions[STIX_EXT_OCTI].participant_ids = baseData.extensions[STIX_EXT_OCTI].participant_ids;
      }
      if (baseData.extensions[STIX_EXT_OCTI].assignee_ids) {
        container.extensions[STIX_EXT_OCTI].assignee_ids = baseData.extensions[STIX_EXT_OCTI].assignee_ids;
      }
      // if the base instance is an incident and we wrap into an Incident Case, we set the same severity
      if ((<StixIncident>baseData) && container_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
        (<StixCaseIncident>container).severity = (<StixIncident>baseData).severity;
        (<StixCaseIncident>container).external_references = (<StixIncident>baseData).external_references;
        (<StixCaseIncident>container).extensions[STIX_EXT_OCTI].granted_refs = (<StixIncident>baseData).extensions[STIX_EXT_OCTI].granted_refs;
      }
      // Copy files from the main element to the container if requested
      const stixFileExtensions = baseData.extensions[STIX_EXT_OCTI].files;
      if (copyFiles && stixFileExtensions && stixFileExtensions.length > 0) {
        // We need to get the files and add the data inside
        const copiedFiles = [];
        for (let index = 0; index < stixFileExtensions.length; index += 1) {
          const currentFile = stixFileExtensions[index];
          // If data already available, just apply no_trigger_import
          if (currentFile.data !== undefined && currentFile.data !== null) {
            copiedFiles.push({ ...currentFile, no_trigger_import: true });
          } else {
            // If data not in the element, fetch it in base64
            const currentFileUri = currentFile.uri;
            try {
              const fileId = currentFileUri.replace('/storage/get/', '');
              const currentFileContent = await getFileContent(fileId, 'base64');
              copiedFiles.push({ ...currentFile, data: currentFileContent, no_trigger_import: true });
            } catch (e) {
              logApp.error("[PLAYBOOK] Can't copy file from main element to the container", { cause: e, name: currentFile.name });
            }
          }
        }
        container.extensions[STIX_EXT_OCTI].files = copiedFiles;
      }
      if (STIX_DOMAIN_OBJECT_CONTAINER_CASES.includes(container_type) && caseTemplates.length > 0) {
        const tasks = await createTaskFromCaseTemplates(caseTemplates, (container as StixContainer));
        pushAll(bundle.objects, tasks);
      }
      bundle.objects.push(container);
    }
    return { output_port: 'out', bundle };
  },
};
