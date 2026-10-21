import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixId } from '../../types/stix-2-1-common';
import {
  ENTITY_TYPE_IOC_VALIDATION_REQUEST,
  type IocValidationIoc,
  STIX_IOC_VALIDATION_REQUEST_TYPE,
  type StixIocValidationRequest,
  type StoreEntityIocValidationRequest,
} from './iocValidation-types';

const convertIocValidationRequestToStix = (instance: StoreEntityIocValidationRequest): StixIocValidationRequest => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    status: instance.status,
    test_kinds: instance.test_kinds,
  };
};

export interface IocValidationBundlePair {
  indicator_ref: StixId;
  platform_ref: StixId;
  deployed_on_ref: StixId;
}

export interface StixIocValidationRequestForOpenAEV {
  type: typeof STIX_IOC_VALIDATION_REQUEST_TYPE;
  id: string;
  spec_version: '2.1';
  created: string;
  modified: string;
  name: string;
  description?: string;
  requested_by: string;
  test_kinds: string[];
  indicator_refs: StixId[];
  platform_refs: StixId[];
  iocs: Array<{
    indicator_ref: StixId;
    observable_type: string;
    value: string;
    test_kind: string;
    file_name: string | null;
    hashes: Record<string, string> | null;
  }>;
  pairs: IocValidationBundlePair[];
  extensions: {
    [STIX_EXT_OCTI]: { extension_type: 'new-sdo'; id: string; type: string };
  };
}

const toIsoString = (value: Date | string | undefined | null) => {
  if (!value) return new Date().toISOString();
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
};

/**
 * Custom STIX object describing the request in the bundle pushed to the OpenAEV IOC validation connector.
 * Contract: OpenCTI-Platform/opencti#18680, section "OpenCTI -> OpenAEV request".
 */
export const buildIocValidationRequestForOpenAEV = (
  request: StoreEntityIocValidationRequest,
  args: { requestedBy: string; indicatorRefs: StixId[]; platformRefs: StixId[]; iocs: IocValidationIoc[]; pairs: IocValidationBundlePair[] },
): StixIocValidationRequestForOpenAEV => ({
  type: STIX_IOC_VALIDATION_REQUEST_TYPE,
  id: `${STIX_IOC_VALIDATION_REQUEST_TYPE}--${request.internal_id}`,
  spec_version: '2.1',
  created: toIsoString(request.created_at),
  modified: toIsoString(request.updated_at),
  name: request.name,
  ...(request.description ? { description: request.description } : {}),
  requested_by: args.requestedBy,
  test_kinds: request.test_kinds,
  indicator_refs: args.indicatorRefs,
  platform_refs: args.platformRefs,
  iocs: args.iocs.map((ioc) => ({
    indicator_ref: ioc.indicator_ref,
    observable_type: ioc.observable_type,
    value: ioc.value,
    test_kind: ioc.test_kind,
    file_name: ioc.file_name ?? null,
    hashes: ioc.hashes ?? null,
  })),
  pairs: args.pairs,
  extensions: {
    [STIX_EXT_OCTI]: { extension_type: 'new-sdo', id: request.internal_id, type: ENTITY_TYPE_IOC_VALIDATION_REQUEST },
  },
});

export default convertIocValidationRequestToStix;
