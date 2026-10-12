import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import gql from 'graphql-tag';
import * as rabbitmq from '../../../src/database/rabbitmq';
import { ADMIN_USER, getAuthUser, getUserIdByEmail, testContext, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { connectorDelete, registerConnector } from '../../../src/domain/connector';
import { askElementEnrichmentForConnectors } from '../../../src/domain/stixCoreObject';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { deleteElementById } from '../../../src/database/middleware';
import { deleteWork, loadWorkById, reportExpectation, updateExpectationsNumber } from '../../../src/domain/work';
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

  describe('bulk enrichment task', () => {
    const LIST_TASK_ADD = gql`mutation listTaskAdd($input: ListTaskAddInput!) { listTaskAdd(input: $input) { id } }`;

    /**
     * Build the input of a bulk enrichment task on knowledge, linked to the given investigation.
     */
    const taskInput = (investigationId: string) => ({
      description: 'Bulk enrichment for investigation',
      ids: [],
      scope: 'KNOWLEDGE',
      actions: [{ type: 'ENRICHMENT', context: { values: [INV_CONNECTOR_A], options: { investigationId } } }],
    });

    it('should accept an editor of the investigation with the enrichment capability', async () => {
      await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, { query: LIST_TASK_ADD, variables: { input: taskInput(editableInvestigationId) } });
    });

    it('should refuse a view-only member', async () => {
      await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST, { query: LIST_TASK_ADD, variables: { input: taskInput(viewOnlyInvestigationId) } });
    });

    it('should refuse a user without the enrichment capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: LIST_TASK_ADD, variables: { input: taskInput(editableInvestigationId) } });
    });
  });

  describe('retrieval', () => {
    const ENRICHMENT_WORKS = gql`
      query EnrichmentWorks($id: String!, $first: Int, $after: ID, $filters: FilterGroup) {
        workspace(id: $id) {
          enrichmentWorks(first: $first, after: $after, filters: $filters) {
            edges { node { id status connector { id } } }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    `;
    const WORKS = gql`
      query Works($filters: FilterGroup) { works(first: 50, filters: $filters) { edges { node { id } } } }
    `;
    const TLP_RED = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed';
    let otherInvestigationId: string;
    const tagged: string[] = [];
    // Dedicated to single tests, so that the expectations on otherInvestigationId stay unchanged
    const dedicatedInvestigationIds: string[] = [];
    const dedicatedIntrusionSetIds: string[] = [];

    beforeAll(async () => {
      otherInvestigationId = await createWorkspace('investigation', 'Other enrichment investigation', 'edit');
      const fromA: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: otherInvestigationId });
      const fromB: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_B], { investigationId: otherInvestigationId });
      const another: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: otherInvestigationId });
      tagged.push(fromA[0].id, fromB[0].id, another[0].id);
      workIds.push(...tagged);
      // Complete the first work only
      await updateExpectationsNumber(testContext, ADMIN_USER, fromA[0].id, 1);
      await reportExpectation(testContext, ADMIN_USER, fromA[0].id);
    });

    afterAll(async () => {
      for (const id of [otherInvestigationId, ...dedicatedInvestigationIds]) {
        await queryAsAdmin({ query: DELETE_WORKSPACE, variables: { id } });
      }
      for (const id of dedicatedIntrusionSetIds) {
        await deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_INTRUSION_SET);
      }
    });

    /**
     * List the ids of the enrichment works of an investigation, as admin or as the given user.
     */
    const listEnrichmentWorkIds = async (investigationId: string, asUser?: typeof USER_DISINFORMATION_ANALYST) => {
      const query = { query: ENRICHMENT_WORKS, variables: { id: investigationId, first: 50 } };
      const result = asUser ? await queryAsUserWithSuccess(asUser, query) : await queryAsAdminWithSuccess(query);
      return result.data?.workspace.enrichmentWorks.edges.map((e: any) => e.node.id).sort();
    };

    it('should list the works of the investigation from the works query', async () => {
      const filters = { mode: 'and', filters: [{ key: 'investigation_id', values: [otherInvestigationId] }], filterGroups: [] };
      const result = await queryAsAdminWithSuccess({ query: WORKS, variables: { filters } });
      expect(result.data?.works.edges.map((e: any) => e.node.id).sort()).toEqual([...tagged].sort());
    });

    it('should list the works of the investigation from the workspace', async () => {
      const result = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 50 } });
      expect(result.data?.workspace.enrichmentWorks.edges.map((e: any) => e.node.id).sort()).toEqual([...tagged].sort());
    });

    it('should combine caller filters with the investigation', async () => {
      const filters = {
        mode: 'and',
        filters: [{ key: 'status', values: ['complete'] }, { key: 'connector_id', values: [INV_CONNECTOR_A] }],
        filterGroups: [],
      };
      const result = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 50, filters } });
      expect(result.data?.workspace.enrichmentWorks.edges.map((e: any) => e.node.id)).toEqual([tagged[0]]);
    });

    it('should let a reader of the investigation without the MODULES capability list its works', async () => {
      // The analyst (anais) has no MODULES capability, so the root works query is forbidden to this user
      expect(analyst.capabilities.some((c: any) => c.name.startsWith('MODULES'))).toBe(false);
      await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST, { query: WORKS, variables: { filters: undefined } });
      const result = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, { query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 50 } });
      expect(result.data?.workspace.enrichmentWorks.edges.map((e: any) => e.node.id).sort()).toEqual([...tagged].sort());
    });

    it('should keep the investigation filter when the caller uses an OR group', async () => {
      const filters = {
        mode: 'or',
        filters: [{ key: 'investigation_id', values: [editableInvestigationId] }, { key: 'status', values: ['complete'] }],
        filterGroups: [],
      };
      const result = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 50, filters } });
      expect(result.data?.workspace.enrichmentWorks.edges.map((e: any) => e.node.id)).toEqual([tagged[0]]);
    });

    it('should never return works of another investigation', async () => {
      const filters = { mode: 'and', filters: [{ key: 'investigation_id', values: [editableInvestigationId] }], filterGroups: [] };
      const result = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 50, filters } });
      expect(result.data?.workspace.enrichmentWorks.edges).toEqual([]);
    });

    it('should return an empty connection for a dashboard', async () => {
      const result = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: dashboardId, first: 50 } });
      expect(result.data?.workspace.enrichmentWorks.edges).toEqual([]);
    });

    it('should paginate every work exactly once', async () => {
      const page1 = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 2 } });
      const first = page1.data?.workspace.enrichmentWorks;
      expect(first.edges).toHaveLength(2);
      expect(first.pageInfo.hasNextPage).toBe(true);
      const page2 = await queryAsAdminWithSuccess({ query: ENRICHMENT_WORKS, variables: { id: otherInvestigationId, first: 2, after: first.pageInfo.endCursor } });
      const second = page2.data?.workspace.enrichmentWorks;
      const ids = [...first.edges, ...second.edges].map((e: any) => e.node.id);
      expect(new Set(ids).size).toBe(3);
      expect(ids.sort()).toEqual([...tagged].sort());
    });

    it('should tag the work with the internal id when the investigation is given by its standard id', async () => {
      const investigationId = await createWorkspace('investigation', 'Enrichment investigation (standard id)', 'edit');
      dedicatedInvestigationIds.push(investigationId);
      const loaded = await queryAsAdminWithSuccess({ query: gql`query W($id: String!) { workspace(id: $id) { standard_id } }`, variables: { id: investigationId } });
      const standardId = loaded.data?.workspace.standard_id;
      expect(standardId).not.toEqual(investigationId);
      const works: any[] = await askElementEnrichmentForConnectors(testContext, analyst, enriched.id, [INV_CONNECTOR_A], { investigationId: standardId });
      workIds.push(works[0].id);
      expect(((await loadWorkById(testContext, ADMIN_USER, works[0].id)) as any).investigation_id).toEqual(investigationId);
      expect(await listEnrichmentWorkIds(investigationId)).toEqual([works[0].id]);
    });

    it('should hide the works of an enriched entity the reader cannot load', async () => {
      // The analyst only has the TLP:GREEN marking
      expect(analyst.allowed_marking.some((m: any) => m.standard_id === TLP_RED)).toBe(false);
      const investigationId = await createWorkspace('investigation', 'Enrichment investigation (hidden entity)', 'view');
      dedicatedInvestigationIds.push(investigationId);
      const hidden = await addIntrusionSet(testContext, ADMIN_USER, { name: `Investigation hidden ${Date.now()}`, objectMarking: [TLP_RED] });
      dedicatedIntrusionSetIds.push(hidden.id);
      const [visibleWork]: any[] = await askElementEnrichmentForConnectors(testContext, ADMIN_USER, enriched.id, [INV_CONNECTOR_A], { investigationId });
      const [hiddenWork]: any[] = await askElementEnrichmentForConnectors(testContext, ADMIN_USER, hidden.id, [INV_CONNECTOR_A], { investigationId });
      workIds.push(visibleWork.id, hiddenWork.id);
      expect(await listEnrichmentWorkIds(investigationId)).toEqual([visibleWork.id, hiddenWork.id].sort());
      expect(await listEnrichmentWorkIds(investigationId, USER_DISINFORMATION_ANALYST)).toEqual([visibleWork.id]);
    });
  });
});
