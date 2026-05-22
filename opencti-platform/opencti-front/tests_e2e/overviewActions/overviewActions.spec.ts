import { expect, test } from '../fixtures/baseFixtures';

type OverviewRouteCheck = {
  label: string;
  listPath: string;
  entityName: string;
  hasSecurityCoverageAction?: boolean;
};

const OVERVIEW_ROUTE_CHECKS: OverviewRouteCheck[] = [
  {
    label: 'Campaign',
    listPath: '/dashboard/threats/campaigns',
    entityName: 'A new campaign',
    hasSecurityCoverageAction: true,
  },
  {
    label: 'Intrusion set',
    listPath: '/dashboard/threats/intrusion_sets',
    entityName: 'E2E dashboard - Intrusion set - now',
    hasSecurityCoverageAction: true,
  },
  {
    label: 'Threat actor group',
    listPath: '/dashboard/threats/threat_actors_group',
    entityName: 'Disco Team Threat Actor Group',
  },
  {
    label: 'Threat actor individual',
    listPath: '/dashboard/threats/threat_actors_individual',
    entityName: 'E2E dashboard - Threat actor - now',
  },
  {
    label: 'Malware',
    listPath: '/dashboard/arsenal/malwares',
    entityName: 'E2E dashboard - Malware - now',
  },
  {
    label: 'Sector',
    listPath: '/dashboard/entities/sectors',
    entityName: 'Sector e2e',
  },
  {
    label: 'Incident',
    listPath: '/dashboard/events/incidents',
    entityName: 'Incident Name',
    hasSecurityCoverageAction: true,
  },
  {
    label: 'Country',
    listPath: '/dashboard/locations/countries',
    entityName: 'Country e2e',
  },
  {
    label: 'Region',
    listPath: '/dashboard/locations/regions',
    entityName: 'Region e2e',
  },
];

test('Overview routes display action buttons', { tag: ['@ce', '@navigation'] }, async ({ page }) => {
  for (const routeCheck of OVERVIEW_ROUTE_CHECKS) {
    await page.goto(routeCheck.listPath);
    const entityLink = page.getByRole('link', { name: routeCheck.entityName });
    await expect(entityLink, `${routeCheck.label} list should contain ${routeCheck.entityName}`).toBeVisible();
    await entityLink.click();

    await page.getByRole('tab', { name: 'Overview' }).click();

    const aiInsightsButton = page.getByLabel('AI Insights', { exact: true });
    await expect(aiInsightsButton, `${routeCheck.label} overview should display AI Insights button`).toBeVisible();

    if (routeCheck.hasSecurityCoverageAction) {
      const addCoverageButton = page.getByRole('button', { name: 'Create a coverage' });
      const existingCoverageLink = page.locator('a[href*="/dashboard/analyses/security_coverages/"]');
      const hasAddCoverage = await addCoverageButton.isVisible().catch(() => false);

      if (hasAddCoverage) {
        await expect(addCoverageButton, `${routeCheck.label} overview should display security coverage button`).toBeVisible();
      } else {
        await expect(existingCoverageLink.first(), `${routeCheck.label} overview should display security coverage button`).toBeVisible();
      }
    }
  }
});
