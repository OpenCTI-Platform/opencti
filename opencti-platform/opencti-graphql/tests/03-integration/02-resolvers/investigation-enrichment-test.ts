import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import gql from 'graphql-tag';
import * as rabbitmq from '../../../src/database/rabbitmq';
import { ADMIN_USER, getAuthUser, getUserIdByEmail, testContext, USER_DISINFORMATION_ANALYST } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { connectorDelete, registerConnector } from '../../../src/domain/connector';
import { askElementEnrichmentForConnectors } from '../../../src/domain/stixCoreObject';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { deleteElementById } from '../../../src/database/middleware';
import { deleteWork, loadWorkById } from '../../../src/domain/work';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ConnectorType } from '../../../src/generated/graphql';

const INV_CONNECTOR_A = 'cc6d8f3a-1b2c-4d5e-8f90-111111111111';
const INV_CONNECTOR_B = 'cc6d8f3a-1b2c-4d5e-8f90-222222222222';

const CREATE_WORKSPACE = gql`mutation WorkspaceAdd($input: WorkspaceAddInput!) { workspaceAdd(input: $input) { id } }`;
const DELETE_WORKSPACE = gql`mutation workspaceDelete($id: ID!) { workspaceDelete(id: $id) }`;
const UPDATE_MEMBERS = gql`
  mutation workspaceEditAuthorizedMembers($id: ID!, $input: [MemberAccessInput!]!) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) { id }
  }
`;
const ASK_ENRICHMENT = gql`
  mutation AskEnrichment($id: ID!, $connectorId: ID!, $investigationId: ID) {
    stixCoreObjectEdit(id: $id) { askEnrichment(connectorId: $connectorId, investigationId: $investigationId) { id } }
  }
`;

describe('Enrichments linked to an investigation', () => {
  let pushToConnector: MockInstance;
  let analyst: any;
  let enriched: any;
  let editableInvestigationId: string;
  let viewOnlyInvestigationId: string;
  let dashboardId: string;
  const workIds: string[] = [];

  /**
   * Create a workspace as admin and optionally share it with the analyst user using the given access right.
   */
  const createWorkspace = async (type: string, name: string, analystRight?: string) => {
    const result = await queryAsAdmin({ query: CREATE_WORKSPACE, variables: { input: { type, name } } });
    const id = result.data?.workspaceAdd.id;
    if (analystRight) {
      await queryAsAdmin({
        query: UPDATE_MEMBERS,
        variables: { id, input: [{ id: ADMIN_USER.id, access_right: 'admin' }, { id: analyst.id, access_right: analystRight }] },
      });
    }
    return id;
  };

  beforeAll(async () => {
    analyst = await getAuthUser(await getUserIdByEmail(USER_DISINFORMATION_ANALYST.email));
    for (const [id, name] of [[INV_CONNECTOR_A, 'Investigation enrichment A'], [INV_CONNECTOR_B, 'Investigation enrichment B']]) {
      await registerConnector(testContext, ADMIN_USER, { id, name, type: ConnectorType.InternalEnrichment, scope: [ENTITY_TYPE_INTRUSION_SET], auto: false }, { active: true });
    }
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    enriched = await addIntrusionSet(testContext, ADMIN_USER, { name: `Investigation enriched ${Date.now()}` });
    editableInvestigationId = await createWorkspace('investigation', 'Enrichment investigation (edit)', 'edit');
    viewOnlyInvestigationId = await createWorkspace('investigation', 'Enrichment investigation (view)', 'view');
    dashboardId = await createWorkspace('dashboard', 'Enrichment dashboard');
  });

  beforeEach(() => {
    pushToConnector = vi.spyOn(rabbitmq, 'pushToConnector').mockResolvedValue(undefined as never);
    return () => {
      vi.restoreAllMocks();
    };
  });

  afterAll(async () => {
    for (const id of workIds) {
      await deleteWork(testContext, ADMIN_USER, id).catch(() => {});
    }
    for (const id of [editableInvestigationId, viewOnlyInvestigationId, dashboardId]) {
      await queryAsAdmin({ query: DELETE_WORKSPACE, variables: { id } });
    }
    await deleteElementById(testContext, ADMIN_USER, enriched.id, ENTITY_TYPE_INTRUSION_SET);
    await connectorDelete(testContext, ADMIN_USER, INV_CONNECTOR_A);
    await connectorDelete(testContext, ADMIN_USER, INV_CONNECTOR_B);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should tag every work created by askEnrichments', async () => {
    const connectorIds = [INV_CONNECTOR_A, INV_CONNECTOR_B];
    const works: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, connectorIds, { investigationId: editableInvestigationId });
    workIds.push(...works.map((w: any) => w.id));
    expect(works).toHaveLength(2);
    for (const work of works) {
      const stored: any = await loadWorkById(testContext, ADMIN_USER, work.id);
      expect(stored.investigation_id).toEqual(editableInvestigationId);
    }
  });

  it('should tag the work through the GraphQL argument', async () => {
    const result = await queryAsAdminWithSuccess({
      query: ASK_ENRICHMENT,
      variables: { id: enriched.id, connectorId: INV_CONNECTOR_A, investigationId: editableInvestigationId },
    });
    const workId = result.data?.stixCoreObjectEdit.askEnrichment.id;
    workIds.push(workId);
    expect(((await loadWorkById(testContext, ADMIN_USER, workId)) as any).investigation_id).toEqual(editableInvestigationId);
  });

  it('should refuse a workspace that is not an investigation', async () => {
    await expect(askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: dashboardId }))
      .rejects.toThrow('Investigation not found');
    expect(pushToConnector).not.toHaveBeenCalled();
  });

  it('should refuse an unknown investigation', async () => {
    await expect(askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: 'unknown-investigation' }))
      .rejects.toThrow('Investigation not found');
  });

  it('should refuse a view-only member', async () => {
    await expect(askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: viewOnlyInvestigationId }))
      .rejects.toThrow('You are not allowed to do this.');
    expect(pushToConnector).not.toHaveBeenCalled();
  });

  it('should refuse a user without the investigation update capability', async () => {
    const withoutInvestigation = { ...analyst, capabilities: analyst.capabilities.filter((c: any) => !c.name.startsWith('INVESTIGATION')) };
    await expect(askElementEnrichmentForConnectors(testContext, withoutInvestigation, enriched.id, [INV_CONNECTOR_A], { investigationId: editableInvestigationId }))
      .rejects.toThrow('You are not allowed to do this.');
  });

  it('should ignore an empty investigation id', async () => {
    const works: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: '' });
    workIds.push(works[0].id);
    expect(((await loadWorkById(testContext, ADMIN_USER, works[0].id)) as any).investigation_id).toBeUndefined();
  });

  it('should refuse a connector that is not an enrichment connector', async () => {
    const importConnectorId = 'cc6d8f3a-1b2c-4d5e-8f90-333333333333';
    await registerConnector(
      testContext,
      ADMIN_USER,
      { id: importConnectorId, name: 'Investigation import connector', type: ConnectorType.ExternalImport, scope: [] },
      { active: true },
    );
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);

    try {
      await expect(askElementEnrichmentForConnectors(
        testContext,
        analyst,
        enriched.id,
        [INV_CONNECTOR_A, importConnectorId],
        { investigationId: editableInvestigationId },
      )).rejects.toThrow('Only enrichment connectors can enrich an element');
      expect(pushToConnector).not.toHaveBeenCalled();
    } finally {
      await connectorDelete(testContext, ADMIN_USER, importConnectorId);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should refuse a deleted investigation', async () => {
    const deletedId = await createWorkspace('investigation', 'Enrichment investigation (deleted)', 'edit');
    await queryAsAdmin({ query: DELETE_WORKSPACE, variables: { id: deletedId } });
    await expect(askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: deletedId }))
      .rejects.toThrow('Investigation not found');
    expect(pushToConnector).not.toHaveBeenCalled();
  });
});
