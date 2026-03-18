import { describe, expect, it } from 'vitest';
import { PLAYBOOK_SECURITY_COVERAGE_COMPONENT } from '../../../../src/modules/playbook/components/security-coverage-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import type { StixSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

const MAIN_ID = 'report--b4754e7d-88b4-51d9-aac4-86edaad66c4d';
const INTRUSION_SET_ID = 'intrusion-set--1ad04810-ab05-5873-96f5-a89d19607e1c';
const CAMPAIGN_ID = 'campaign--c85bcdd3-1042-5f74-ab5d-05fddf30bdb8';

const enteringBundleObjects = [
  testBundleObject({
    id: MAIN_ID,
    type: 'report',
    extension: { type: 'Report' },
    object_refs: [
      INTRUSION_SET_ID,
      CAMPAIGN_ID,
    ],
  }),
  testBundleObject({
    id: INTRUSION_SET_ID,
    type: 'intrusion-set',
    extension: { type: 'Intrusion-Set' },
  }),
  testBundleObject({
    id: CAMPAIGN_ID,
    type: 'campaign',
    extension: { type: 'Campaign' },
  }),
];

const componentConfig = ({ elementsToApply }: { elementsToApply: PlaybookBundleElementsToApply }) => {
  return {
    applyToElements: elementsToApply,
    auto_enrichment_disable: false,
    duration: 'P30D',
    periodicity: 'P1D',
    platforms_affinity: ['windows', 'linux', 'macos'],
    type_affinity: 'ENDPOINT',
  };
};

describe('Security coverage component', () => {
  it('should create a security coverage only for main element with the only main option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: MAIN_ID,
        bundleObjects: enteringBundleObjects,
        configuration: componentConfig({ elementsToApply: playbookBundleElementsToApply.onlyMain.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(1);
    expect(securityCoverages[0].covered_ref).toEqual(MAIN_ID);
  });

  it('should create a security coverage for each element of the bundle with the all elements option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: MAIN_ID,
        bundleObjects: enteringBundleObjects,
        configuration: componentConfig({ elementsToApply: playbookBundleElementsToApply.allElements.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(3);

    const mainElementSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === MAIN_ID);
    const intrusionSetSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === INTRUSION_SET_ID);
    const campaignSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === CAMPAIGN_ID);

    expect(mainElementSecurityCoverage).toHaveLength(1);
    expect(intrusionSetSecurityCoverage).toHaveLength(1);
    expect(campaignSecurityCoverage).toHaveLength(1);
  });

  it('should create a security coverage for each element except main with the all except main option', async () => {
    const result = await PLAYBOOK_SECURITY_COVERAGE_COMPONENT.executor(
      testExecutor({
        mainId: MAIN_ID,
        bundleObjects: enteringBundleObjects,
        configuration: componentConfig({ elementsToApply: playbookBundleElementsToApply.allExceptMain.value }),
      }),
    );

    const securityCoverages = result.bundle.objects.filter(
      (o) => o.type === 'security-coverage',
    ) as StixSecurityCoverage[];

    expect(securityCoverages).toHaveLength(2);

    const mainElementSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === MAIN_ID);
    const intrusionSetSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === INTRUSION_SET_ID);
    const campaignSecurityCoverage = securityCoverages.filter((o) => o.covered_ref === CAMPAIGN_ID);

    expect(mainElementSecurityCoverage).toHaveLength(0);
    expect(intrusionSetSecurityCoverage).toHaveLength(1);
    expect(campaignSecurityCoverage).toHaveLength(1);
  });
});
