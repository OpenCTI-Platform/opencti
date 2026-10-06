import { afterAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { IngestionAuthType, TaxiiVersion } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext, USER_DISINFORMATION_ANALYST } from '../../utils/testQuery';
import { findById as findTaxiiIngestionById } from '../../../src/modules/ingestion/ingestion-taxii-domain';
import { ENTITY_TYPE_INGESTION_TAXII } from '../../../src/modules/ingestion/ingestion-types';
import { patchAttribute } from '../../../src/database/middleware';
import { pushBundleToConnectorQueue } from '../../../src/manager/ingestionManager';
import * as rabbitmq from '../../../src/database/rabbitmq';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { StixBundle } from '../../../src/types/stix-2-1-common';

const REJECTION_MESSAGE = 'You are not allowed to use this user for this ingestion';

const CREATE_TAXII_INGESTION = gql`
  mutation createTaxiiIngestion($input: IngestionTaxiiAddInput!) {
    ingestionTaxiiAdd(input: $input) {
      id
      user_id
    }
  }
`;

const PATCH_TAXII_INGESTION = gql`
  mutation patchTaxiiIngestion($id: ID!, $input: [EditInput!]!) {
    ingestionTaxiiFieldPatch(id: $id, input: $input) {
      id
      user_id
    }
  }
`;

const DELETE_TAXII_INGESTION = gql`
  mutation deleteTaxiiIngestion($id: ID!) {
    ingestionTaxiiDelete(id: $id)
  }
`;

const taxiiInput = (name: string, userId: string) => ({
  authentication_type: IngestionAuthType.None,
  name,
  version: TaxiiVersion.V21,
  collection: 'TaxiiCollection',
  uri: 'http://taxiiserver.invalid',
  user_id: userId,
});

// A user only granted the ingestion management capability must never be able to run a feed with more rights than its own.
describe('Ingestion execution identity - feed identity confined to its creator rights (#18637)', () => {
  const createdIngestionIds: string[] = [];

  afterAll(async () => {
    vi.restoreAllMocks();
    for (let i = 0; i < createdIngestionIds.length; i += 1) {
      await queryAsAdminWithSuccess({ query: DELETE_TAXII_INGESTION, variables: { id: createdIngestionIds[i] } });
    }
  });

  it('should creation of a feed running as an administrator be refused to a user managing ingestions', async () => {
    const result = await queryAsUser(USER_DISINFORMATION_ANALYST.client, {
      query: CREATE_TAXII_INGESTION,
      variables: { input: taxiiInput('Taxii feed running as administrator', ADMIN_USER.id) },
    });
    const created = result.data?.ingestionTaxiiAdd;
    if (created) {
      createdIngestionIds.push(created.id);
    }
    expect(created, `Feed created by the analyst with the identity ${created?.user_id}`).toBeFalsy();
    expect(result.errors?.[0]?.message).toBe(REJECTION_MESSAGE);
  });

  it('should switching an existing feed to an administrator identity be refused to a user managing ingestions', async () => {
    const creation = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: CREATE_TAXII_INGESTION,
      variables: { input: taxiiInput('Taxii feed running as the analyst', USER_DISINFORMATION_ANALYST.id) },
    });
    const ingestionId = creation.data?.ingestionTaxiiAdd.id;
    createdIngestionIds.push(ingestionId);

    const result = await queryAsUser(USER_DISINFORMATION_ANALYST.client, {
      query: PATCH_TAXII_INGESTION,
      variables: { id: ingestionId, input: [{ key: 'user_id', value: [ADMIN_USER.id] }] },
    });
    const patched = result.data?.ingestionTaxiiFieldPatch;
    expect(patched, `Feed switched by the analyst to the identity ${patched?.user_id}`).toBeFalsy();
    expect(result.errors?.[0]?.message).toBe(REJECTION_MESSAGE);
    const stored = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionId);
    expect(stored.user_id).toBe(USER_DISINFORMATION_ANALYST.id);
  });

  it('should a stored feed whose identity exceeds its creator rights never be pushed to the worker', async () => {
    const creation = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST.client, {
      query: CREATE_TAXII_INGESTION,
      variables: { input: taxiiInput('Taxii feed with a privileged stored identity', USER_DISINFORMATION_ANALYST.id) },
    });
    const ingestionId = creation.data?.ingestionTaxiiAdd.id;
    createdIngestionIds.push(ingestionId);
    // Simulates a feed stored before the creation and edition checks existed.
    await patchAttribute(testContext, SYSTEM_USER, ingestionId, ENTITY_TYPE_INGESTION_TAXII, { user_id: ADMIN_USER.id });
    const ingestion = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionId);

    const pushSpy = vi.spyOn(rabbitmq, 'pushToWorkerForConnector').mockResolvedValue(true);
    const bundle = { id: 'bundle--8f0a4c8e-6b3c-4f1e-9d3a-2a4b5c6d7e8f', type: 'bundle', objects: [] } as unknown as StixBundle;
    let pushError: Error | undefined;
    try {
      await pushBundleToConnectorQueue(testContext, ingestion, bundle);
    } catch (err) {
      pushError = err as Error;
    }
    const applicantIds = pushSpy.mock.calls.map(([, message]: any[]) => message.applicant_id);
    expect(applicantIds, 'Bundle pushed to the worker under the administrator identity').not.toContain(ADMIN_USER.id);
    expect(pushError?.message).toBe(REJECTION_MESSAGE);
  });
});
