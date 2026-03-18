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

const createFallbackReport = async (request: APIRequestContext) => {
  const reportName = `E2E Fallback Report ${uuid()}`;
  const response = await request.post('/graphql', {
    data: {
      query: `
        mutation SecurityCoverageResultE2ECreateFallbackReport {
          reportAdd(input: {
            name: "${reportName}",
            description: "Fallback report for security coverage E2E"
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

  return payload.data?.reportAdd?.id as string | undefined;
};

const deleteFallbackReport = async (request: APIRequestContext, reportId: string) => {
  await request.post('/graphql', {
    data: {
      query: `
        mutation SecurityCoverageResultE2EDeleteFallbackReport {
          reportEdit(id: "${reportId}") {
            delete
          }
        }
      `,
    },
  });
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

const waitForSecurityCoverageReady = async (request: APIRequestContext, securityCoverageId: string) => {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const response = await request.post('/graphql', {
      data: {
        query: `
          query SecurityCoverageResultE2EWaitReady {
            securityCoverage(id: "${securityCoverageId}") {
              id
            }
          }
        `,
      },
    });

    if (response.ok()) {
      const payload = await response.json();
      if (!payload.errors?.length && payload.data?.securityCoverage?.id === securityCoverageId) {
        return;
      }
    }

    await new Promise((resolve) => {
      setTimeout(resolve, 1000);
    });
  }

  throw new Error(`Security coverage ${securityCoverageId} was not ready before timeout`);
};

test('Security coverage result page renders and shows global metric tooltip', { tag: ['@ce'] }, async ({ page, request }) => {
  let fallbackReportId: string | undefined;
  let objectCoveredId = await getFirstStixCoreObjectId(request);
  if (!objectCoveredId) {
    fallbackReportId = await createFallbackReport(request);
    objectCoveredId = fallbackReportId;
  }
  expect(objectCoveredId).toBeTruthy();

  const securityCoverageId = await createSecurityCoverage(request, objectCoveredId as string);
  expect(securityCoverageId).toBeTruthy();
  await waitForSecurityCoverageReady(request, securityCoverageId as string);

  try {
    await page.goto(`/dashboard/analyses/security_coverages/${securityCoverageId}/result`);

    const resultContainer = page.getByTestId('security-coverage-result-page');
    await expect(resultContainer).toBeVisible();

    await expect(resultContainer.getByText('Type', { exact: true })).toBeVisible();
    await expect(resultContainer.getByText('Name', { exact: true })).toBeVisible();
    await expect(resultContainer.getByText('Coverage', { exact: true })).toBeVisible();
    await expect(resultContainer.getByText('Labels', { exact: true })).toBeVisible();
    await expect(resultContainer.getByText('Marking', { exact: true })).toBeVisible();

    await expect(page.getByRole('button', { name: /Coverage Result Metric/i })).toBeVisible();
  } finally {
    if (securityCoverageId) {
      await deleteSecurityCoverage(request, securityCoverageId);
    }
    if (fallbackReportId) {
      await deleteFallbackReport(request, fallbackReportId);
    }
  }
});


