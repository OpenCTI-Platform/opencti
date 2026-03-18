import { APIRequestContext } from '@playwright/test';
import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';

const getFirstStixCoreObjectId = async (request: APIRequestContext) => {
  const response = await request.post('/graphql', {
    data: {
      query: `
        query SecurityCoverageResultE2EGetFirstObject {
          stixCoreObjects(first: 1) {
            edges {
              node {
                id
              }
            }
          }
        }
      `,
    },
  });

  expect(response.ok()).toBeTruthy();
  const payload = await response.json();
  expect(payload.errors ?? []).toEqual([]);

  return payload.data?.stixCoreObjects?.edges?.[0]?.node?.id as string | undefined;
};

const createSecurityCoverage = async (request: APIRequestContext, objectCoveredId: string) => {
  const name = `E2E Security Coverage ${uuid()}`;
  const response = await request.post('/graphql', {
    data: {
      query: `
        mutation SecurityCoverageResultE2ECreate {
          securityCoverageAdd(input: {
            name: "${name}",
            description: "Security coverage created by Playwright E2E test",
            objectCovered: "${objectCoveredId}",
            coverage_information: [{ coverage_name: "Detection", coverage_score: 75 }],
            periodicity: "P1D",
            duration: "P30D",
            type_affinity: "ENDPOINT",
            platforms_affinity: ["windows"],
            auto_enrichment_disable: true,
            confidence: 50
          }) {
            id
          }
        }
      `,
    },
  });

  expect(response.ok()).toBeTruthy();
  const payload = await response.json();
  expect(payload.errors ?? []).toEqual([]);

  return payload.data?.securityCoverageAdd?.id as string | undefined;
};

const deleteSecurityCoverage = async (request: APIRequestContext, securityCoverageId: string) => {
  await request.post('/graphql', {
    data: {
      query: `
        mutation SecurityCoverageResultE2EDelete {
          securityCoverageDelete(id: "${securityCoverageId}")
        }
      `,
    },
  });
};

test('Security coverage result page renders rows and tooltips', { tag: ['@ce'] }, async ({ page, request }) => {
  const objectCoveredId = await getFirstStixCoreObjectId(request);
  expect(objectCoveredId).toBeTruthy();

  const securityCoverageId = await createSecurityCoverage(request, objectCoveredId as string);
  expect(securityCoverageId).toBeTruthy();

  await page.route('**/graphql', async (route) => {
    const postData = route.request().postDataJSON() as { query?: string } | null;
    const query = postData?.query ?? '';

    if (!query.includes('SecurityCoverageResultLinesPaginationQuery')) {
      await route.continue();
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        data: {
          securityCoverage: {
            id: securityCoverageId,
            entity_type: 'Security-Coverage',
            stixCoreRelationships: {
              edges: [
                {
                  node: {
                    id: `relationship--${uuid()}`,
                    standard_id: `relationship--${uuid()}`,
                    entity_type: 'stix-core-relationship',
                    relationship_type: 'related-to',
                    to: {
                      __typename: 'AttackPattern',
                      id: `attack-pattern--${uuid()}`,
                      draftVersion: null,
                      standard_id: `attack-pattern--${uuid()}`,
                      entity_type: 'Attack-Pattern',
                      created_at: new Date().toISOString(),
                      name: 'Mocked attack pattern',
                      x_mitre_id: 'T1059',
                      objectLabel: [],
                      createdBy: null,
                      objectMarking: [],
                      containersNumber: {
                        total: 0,
                      },
                    },
                    coverage_information: [
                      {
                        coverage_name: 'Detection',
                        coverage_score: 90,
                      },
                    ],
                  },
                },
                {
                  node: {
                    id: `relationship--${uuid()}`,
                    standard_id: `relationship--${uuid()}`,
                    entity_type: 'stix-core-relationship',
                    relationship_type: 'related-to',
                    to: {
                      __typename: 'Report',
                      id: `report--${uuid()}`,
                      draftVersion: null,
                      standard_id: `report--${uuid()}`,
                      entity_type: 'Report',
                      created_at: new Date().toISOString(),
                      name: 'Mocked report without coverage',
                      objectLabel: [],
                      createdBy: null,
                      objectMarking: [],
                      containersNumber: {
                        total: 0,
                      },
                    },
                    coverage_information: [],
                  },
                },
              ],
              pageInfo: {
                endCursor: null,
                hasNextPage: false,
                globalCount: 2,
              },
            },
          },
        },
      }),
    });
  });

  try {
    await page.goto(`/dashboard/analyses/security_coverages/${securityCoverageId}/result`);

    const resultContainer = page.getByTestId('security-coverage-result-page');
    await expect(resultContainer).toBeVisible();

    await expect(page.getByRole('columnheader', { name: 'Type' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Coverage' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Labels' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Marking' })).toBeVisible();

    await expect(page.getByText('[T1059] Mocked attack pattern')).toBeVisible();
    await expect(page.getByText('Mocked report without coverage')).toBeVisible();

    const infoIcon = page.getByTestId('InfoOutlinedIcon');
    await infoIcon.hover();
    await expect(page.getByRole('tooltip')).toContainText('Coverage Result Metric');

    await page.getByText('Mocked report without coverage').hover();
    await page.getByText('-', { exact: true }).first().hover();
    await expect(page.getByRole('tooltip')).toContainText('No executable test are available yet for this entity');
  } finally {
    if (securityCoverageId) {
      await deleteSecurityCoverage(request, securityCoverageId);
    }
  }
});


