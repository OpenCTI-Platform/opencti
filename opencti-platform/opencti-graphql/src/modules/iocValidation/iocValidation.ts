import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import convertIocValidationRequestToStix from './iocValidation-converter';
import {
  ENTITY_TYPE_IOC_VALIDATION_REQUEST,
  IOC_VALIDATION_REQUEST_STATUSES,
  IOC_VALIDATION_TEST_KINDS,
  type StixIocValidationRequest,
  type StoreEntityIocValidationRequest,
} from './iocValidation-types';

const IOC_VALIDATION_REQUEST_DEFINITION: ModuleDefinition<StoreEntityIocValidationRequest, StixIocValidationRequest> = {
  type: {
    id: 'ioc-validation-request',
    name: ENTITY_TYPE_IOC_VALIDATION_REQUEST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_IOC_VALIDATION_REQUEST]: () => uuidv4(),
    },
  },
  attributes: [
    creators,
    createdAt,
    updatedAt,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    {
      name: 'platform_ids',
      label: 'Validated security platforms',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'indicator_ids',
      label: 'Validated indicators',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_INDICATOR],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'test_kinds',
      label: 'Test kinds',
      type: 'string',
      format: 'enum',
      values: [...IOC_VALIDATION_TEST_KINDS],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'status',
      label: 'Validation request status',
      type: 'string',
      format: 'enum',
      values: [...IOC_VALIDATION_REQUEST_STATUSES],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    { name: 'status_message', label: 'Validation request message', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'openaev_scenario_id', label: 'OpenAEV scenario', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'openaev_simulation_id', label: 'OpenAEV simulation', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'external_uri', label: 'External URI', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'connector_id', label: 'Connector ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'work_id', label: 'Work', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'results_summary', label: 'Validation results summary', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'iocs', label: 'Validated IOCs', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'pairs', label: 'Validated deployments', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'skipped', label: 'Skipped validations', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'dispatched_at', label: 'Dispatched at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'completed_at', label: 'Completed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (instance: StixIocValidationRequest) => {
    return instance.name;
  },
  converter_2_1: convertIocValidationRequestToStix,
};

registerDefinition(IOC_VALIDATION_REQUEST_DEFINITION);
