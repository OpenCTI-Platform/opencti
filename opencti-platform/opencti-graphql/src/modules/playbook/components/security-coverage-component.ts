import { v4 as uuidv4 } from 'uuid';
import type { JSONSchemaType } from 'ajv';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { INPUT_LABELS } from '../../../schema/general';
import type { StoreCommon } from '../../../types/store';
import { generateStandardId } from '../../../schema/identifier';
import { now } from '../../../utils/format';
import { getParentTypes } from '../../../schema/schemaUtils';
import type { StixDomainObject } from '../../../types/stix-2-1-common';
import { extractStixRepresentative } from '../../../database/stix-representative';
import { convertStoreToStix_2_1 } from '../../../database/stix-2-1-converter';
import { ENTITY_TYPE_SECURITY_COVERAGE, INPUT_COVERED, type StixSecurityCoverage, type StoreEntitySecurityCoverage } from '../../securityCoverage/securityCoverage-types';
import { isBundleElementInScope } from '../playbook-utils';

export interface SecurityCoverageConfiguration {
  applyToElements: PlaybookBundleElementsToApply;
  auto_enrichment_disable: boolean;
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
}

const PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA: JSONSchemaType<SecurityCoverageConfiguration> = {
  type: 'object',
  properties: {
    applyToElements: {
      type: 'string',
      default: playbookBundleElementsToApply.onlyMain.value,
      $ref: 'Apply to',
      oneOf: [
        { const: playbookBundleElementsToApply.onlyMain.value, title: playbookBundleElementsToApply.onlyMain.title },
        { const: playbookBundleElementsToApply.allElements.value, title: playbookBundleElementsToApply.allElements.title },
        { const: playbookBundleElementsToApply.allExceptMain.value, title: playbookBundleElementsToApply.allExceptMain.title },
      ],
    },
    auto_enrichment_disable: { type: 'boolean', $ref: 'Force manual coverage (prevent enrichment connectors from running)', default: false },
    periodicity: { type: 'string', $ref: 'Coverage recurrence (every x)', default: 'P1D' },
    duration: { type: 'string', $ref: 'Duration', default: 'P30D' },
    type_affinity: {
      type: 'string',
      $ref: 'Type affinity',
      default: 'ENDPOINT',
    },
    platforms_affinity: {
      type: 'array',
      uniqueItems: true,
      default: ['windows', 'linux', 'macos'],
      $ref: 'Platform(s) affinity',
      items: { type: 'string', oneOf: [] },
    },
  },
  required: ['periodicity', 'duration', 'type_affinity', 'platforms_affinity', 'applyToElements'],
};

const SECURITY_COVERAGE_COMPATIBLE_TYPES = [
  'report',
  'grouping',
  'case-incident',
  'x-opencti-case-incident',
  'intrusion-set',
  'campaign',
  'incident',
];

export const PLAYBOOK_SECURITY_COVERAGE_COMPONENT: PlaybookComponent<SecurityCoverageConfiguration> = {
  id: 'PLAYBOOK_SECURITY_COVERAGE_COMPONENT',
  name: 'Security coverage',
  description: 'Create a security coverage for the given entity(ies) (when type is compatible)',
  icon: 'security-coverage',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const { applyToElements, auto_enrichment_disable, periodicity, duration, type_affinity, platforms_affinity } = playbookNode.configuration;

    const elementsToApply = bundle.objects.filter((object) => isBundleElementInScope(object, applyToElements, dataInstanceId));

    for (let index = 0; index < elementsToApply.length; index += 1) {
      const element = elementsToApply[index] as StixDomainObject;
      if (SECURITY_COVERAGE_COMPATIBLE_TYPES.includes(element.type)) {
        const name = extractStixRepresentative(element);
        const isMainElement = element.id === dataInstanceId;

        const securityCoverageData: Record<string, unknown> = {
          name,
          created: now(),
          auto_enrichment_disable: auto_enrichment_disable,
          periodicity: periodicity,
          duration: duration,
          type_affinity: type_affinity,
          ...(isMainElement && { platforms_affinity: platforms_affinity }),
          [INPUT_COVERED]: { standard_id: element.id },
          [INPUT_LABELS]: (element.labels ?? []).map((l) => ({ value: l })),
        };
        const standardId = generateStandardId(ENTITY_TYPE_SECURITY_COVERAGE, securityCoverageData);
        const baseStore = {
          internal_id: uuidv4(),
          standard_id: standardId,
          entity_type: ENTITY_TYPE_SECURITY_COVERAGE,
          parent_types: getParentTypes(ENTITY_TYPE_SECURITY_COVERAGE),
          ...securityCoverageData,
        };

        const store = isMainElement
          ? (baseStore as StoreEntitySecurityCoverage)
          : (baseStore as StoreCommon);

        const securityCoverage = convertStoreToStix_2_1(store) as StixSecurityCoverage;
        bundle.objects.push(securityCoverage);
      }
    }

    return { output_port: 'out', bundle };
  },
};
