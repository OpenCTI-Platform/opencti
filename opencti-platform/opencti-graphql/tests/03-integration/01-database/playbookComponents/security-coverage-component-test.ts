import { describe, expect, it } from 'vitest';
import { PLAYBOOK_SECURITY_COVERAGE_COMPONENT, type SecurityCoverageConfiguration } from '../../../../src/modules/playbook/components/security-coverage-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import type { StixSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';
import type { StixDomainObject } from '../../../../src/types/stix-2-1-common';

const REPORT_ID = 'report--b4754e7d-88b4-51d9-aac4-86edaad66c4d';
const INTRUSION_SET_ID = 'intrusion-set--1ad04810-ab05-5873-96f5-a89d19607e1c';
const CAMPAIGN_ID = 'campaign--c85bcdd3-1042-5f74-ab5d-05fddf30bdb8';
const LABEL_ID = '98d475ca-0f72-4878-8d64-de2e094f007e';

const BUNDLE_OBJECTS = () => [
  testBundleObject<StixDomainObject>({
    id: REPORT_ID,
    type: 'report',
    labels: [LABEL_ID],
    octiExtension: { type: 'Report' },
    object_refs: [
      INTRUSION_SET_ID,
      CAMPAIGN_ID,
    ],
  }),
  testBundleObject({
    id: INTRUSION_SET_ID,
    type: 'intrusion-set',
    octiExtension: { type: 'Intrusion-Set' },
  }),
  testBundleObject({
    id: CAMPAIGN_ID,
    type: 'campaign',
    octiExtension: { type: 'Campaign' },
  }),
];

const componentConfig = (config: Partial<SecurityCoverageConfiguration>) => {
  return {
    applyToElements: playbookBundleElementsToApply.onlyMain.value,
    auto_enrichment_disable: false,
    duration: 'P30D',
    periodicity: 'P1D',
    platforms_affinity: ['windows', 'linux', 'macos'],
    type_affinity: 'ENDPOINT',
    ...config,
  };
};

describe('Security coverage component', () => {
  it('should create a security coverage only for main element with the only main option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({ applyToElements: playbookBundleElementsToApply.onlyMain.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(1);
    expect(securityCoverages[0].covered_ref).toEqual(REPORT_ID);
  });

  it('should create a security coverage for each element of the bundle with the all elements option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({ applyToElements: playbookBundleElementsToApply.allElements.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(3);

    const mainElementSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === REPORT_ID);
    const intrusionSetSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === INTRUSION_SET_ID);
    const campaignSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === CAMPAIGN_ID);

    expect(mainElementSecurityCoverage).toHaveLength(1);
    expect(intrusionSetSecurityCoverage).toHaveLength(1);
    expect(campaignSecurityCoverage).toHaveLength(1);
  });

  it('should create a security coverage for each element except main with the all except main option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({ applyToElements: playbookBundleElementsToApply.allExceptMain.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(2);

    const mainElementSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === REPORT_ID);
    const intrusionSetSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === INTRUSION_SET_ID);
    const campaignSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === CAMPAIGN_ID);

    expect(mainElementSecurityCoverage).toHaveLength(0);
    expect(intrusionSetSecurityCoverage).toHaveLength(1);
    expect(campaignSecurityCoverage).toHaveLength(1);
  });

  describe('Filter elements manipulated', () => {
    const filterGrounping = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Grouping"],"mode":"or"}],"filterGroups":[]}';
    const filterReport = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Report"],"mode":"or"}],"filterGroups":[]}';
    const filterReportCampaign = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Report", "Campaign"],"mode":"or"}],"filterGroups":[]}';
    const filterAll = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Report", "Campaign", "Intrusion-Set"],"mode":"or"}],"filterGroups":[]}';
    const filterLabel = JSON.stringify({ mode: 'or', filters: [{ key: ['objectLabel'], operator: 'eq', values: [LABEL_ID], mode: 'or' }], filterGroups: [] });

    it('should create nothing if no match (only-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
          applyWithFilters: filterGrounping,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(0);
    });

    it('should create for only main if match (only-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
          applyWithFilters: filterAll,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(1);
      expect(securityCoverages[0].covered_ref).toEqual(REPORT_ID);
    });

    it('should create nothing if no match (all-elements)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterGrounping,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(0);
    });

    it('should create only for report and campaign if partial match (all-elements)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterReportCampaign,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(2);
      expect(securityCoverages[0].covered_ref).toEqual(REPORT_ID);
      expect(securityCoverages[1].covered_ref).toEqual(CAMPAIGN_ID);
    });

    it('should create only for element with matching label if partial match (all-elements)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterLabel,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(1);
      expect(securityCoverages[0].covered_ref).toEqual(REPORT_ID);
    });

    it('should create for all elements if full match (all-elements)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterAll,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(3);
      expect(securityCoverages[0].covered_ref).toEqual(REPORT_ID);
      expect(securityCoverages[1].covered_ref).toEqual(INTRUSION_SET_ID);
      expect(securityCoverages[2].covered_ref).toEqual(CAMPAIGN_ID);
    });

    it('should create nothing if no match (all-except-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterGrounping,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(0);
    });

    it('should create nothing if match only main (all-except-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterReport,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(0);
    });

    it('should create only for campaign if partial match (all-except-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterReportCampaign,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(1);
      expect(securityCoverages[0].covered_ref).toEqual(CAMPAIGN_ID);
    });

    it('should create for all elements except main if full match (all-except-main)', async () => {
      const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({
          applyToElements: 'all-except-main',
          applyWithFilters: filterAll,
        }),
      }));

      const securityCoverages = result.bundle.objects
        .filter((o) => o.type === 'security-coverage') as StixSecurityCoverage[];
      expect(securityCoverages).toHaveLength(2);
      expect(securityCoverages[0].covered_ref).toEqual(INTRUSION_SET_ID);
      expect(securityCoverages[1].covered_ref).toEqual(CAMPAIGN_ID);
    });
  });
});
