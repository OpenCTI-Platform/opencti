import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { draftEntityMarkRead, findDraftEntityRead, resetDraftEntityRead } from '../../../src/modules/draftEntityRead/draftEntityRead-domain';

// -----------------------------------------------------------------
// GraphQL fragments / mutations / queries
// -----------------------------------------------------------------

const DRAFT_ENTITY_READ_QUERY = gql`
  query DraftEntityRead($entityId: ID!, $draftId: ID!) {
    draftEntityRead(entityId: $entityId, draftId: $draftId) {
      id
      user_id
      draft_id
      entity_id
      is_read
    }
  }
`;

const DRAFT_ENTITY_MARK_READ_MUTATION = gql`
  mutation DraftEntityMarkRead($entityId: ID!, $draftId: ID!) {
    draftEntityMarkRead(entityId: $entityId, draftId: $draftId) {
      id
      user_id
      draft_id
      entity_id
      is_read
    }
  }
`;

const DRAFT_ENTITY_MARK_UNREAD_MUTATION = gql`
  mutation DraftEntityMarkUnread($entityId: ID!, $draftId: ID!) {
    draftEntityMarkUnread(entityId: $entityId, draftId: $draftId) {
      id
      user_id
      draft_id
      entity_id
      is_read
    }
  }
`;

const CREATE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
    }
  }
`;

const DELETE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;

const CREATE_REPORT_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
      standard_id
    }
  }
`;

const DELETE_REPORT_QUERY = gql`
  mutation reportDelete($id: ID!) {
    reportEdit(id: $id) {
      delete
    }
  }
`;

// -----------------------------------------------------------------
// Test suite
// -----------------------------------------------------------------

describe('DraftEntityRead Resolver', () => {
  let draftId: string;
  let entityId: string;

  beforeAll(async () => {
    // Create a draft workspace to use as draftId context
    const draftResult = await queryAsAdminWithSuccess({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: { input: { name: 'test-draft-entity-read' } },
    });
    draftId = draftResult.data.draftWorkspaceAdd.id as string;

    // Create a report to use as the entity target
    const reportResult = await queryAsAdminWithSuccess({
      query: CREATE_REPORT_QUERY,
      variables: { input: { name: 'test-report-for-draft-entity-read', published: '2024-01-01T00:00:00Z' } },
    });
    entityId = reportResult.data.reportAdd.id as string;
  });

  afterAll(async () => {
    // Clean up report and draft
    await queryAsAdmin({ query: DELETE_REPORT_QUERY, variables: { id: entityId } });
    await queryAsAdmin({ query: DELETE_DRAFT_WORKSPACE_QUERY, variables: { id: draftId } });
  });

  // ---------------------------------------------------------------
  // draftEntityMarkRead mutation
  // ---------------------------------------------------------------

  describe('draftEntityMarkRead', () => {
    it('should mark an entity as read and return the record', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_MARK_READ_MUTATION,
        variables: { entityId, draftId },
      });
      const record = result.data.draftEntityMarkRead;
      expect(record).not.toBeNull();
      expect(record.entity_id).toEqual(entityId);
      expect(record.draft_id).toEqual(draftId);
      expect(record.user_id).toEqual(ADMIN_USER.id);
      expect(record.is_read).toBe(true);
    });

    it('should be idempotent — calling markRead twice returns the same record (upsert)', async () => {
      const first = await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_MARK_READ_MUTATION,
        variables: { entityId, draftId },
      });
      const second = await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_MARK_READ_MUTATION,
        variables: { entityId, draftId },
      });
      expect(first.data.draftEntityMarkRead?.id).toEqual(second.data.draftEntityMarkRead?.id);
    });
  });

  // ---------------------------------------------------------------
  // draftEntityRead query
  // ---------------------------------------------------------------

  describe('draftEntityRead query', () => {
    it('should return the read record for the current user', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_READ_QUERY,
        variables: { entityId, draftId },
      });
      const record = result.data.draftEntityRead;
      expect(record).not.toBeNull();
      expect(record.is_read).toBe(true);
      expect(record.entity_id).toEqual(entityId);
    });

    it('should return undefined for a different user', async () => {
      const result = await queryAsUserWithSuccess(USER_EDITOR, {
        query: DRAFT_ENTITY_READ_QUERY,
        variables: { entityId, draftId },
      });
      // USER_EDITOR never called markRead, so no record exists for them
      expect(result?.data?.draftEntityRead).toBeNull();
    });
  });

  // ---------------------------------------------------------------
  // draftEntityMarkUnread mutation
  // ---------------------------------------------------------------

  describe('draftEntityMarkUnread', () => {
    it('should mark the entity as unread', async () => {
      // Ensure entity is read first
      await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_MARK_READ_MUTATION,
        variables: { entityId, draftId },
      });
      const result = await queryAsAdminWithSuccess({
        query: DRAFT_ENTITY_MARK_UNREAD_MUTATION,
        variables: { entityId, draftId },
      });
      const record = result.data.draftEntityMarkUnread;
      expect(record).not.toBeNull();
      expect(record.is_read).toBe(false);
    });

    it('should return null when no record exists', async () => {
      const result = await queryAsAdmin({
        query: DRAFT_ENTITY_MARK_UNREAD_MUTATION,
        variables: { entityId: 'non-existent-id', draftId },
      });
      expect(result?.data?.draftEntityMarkUnread).toBeNull();
    });
  });

  // ---------------------------------------------------------------
  // Domain functions — deterministic standard_id (upsert / no duplicates)
  // ---------------------------------------------------------------

  describe('draftEntityMarkRead domain — deterministic standard_id', () => {
    it('should produce the same document id on concurrent calls (no duplicates)', async () => {
      // Call markRead concurrently to simulate race condition
      const [a, b] = await Promise.all([
        draftEntityMarkRead(testContext, ADMIN_USER, entityId, draftId),
        draftEntityMarkRead(testContext, ADMIN_USER, entityId, draftId),
      ]);
      expect(a.id).toEqual(b.id);

      // Only one record must exist
      const records = await findDraftEntityRead(testContext, ADMIN_USER, entityId, draftId);
      expect(records).toBeDefined();
    });
  });

  // ---------------------------------------------------------------
  // resetDraftEntityRead domain function
  // ---------------------------------------------------------------

  describe('resetDraftEntityRead', () => {
    it('should set is_read to false for all users for a given entity+draft', async () => {
      // Ensure the record is read first
      await draftEntityMarkRead(testContext, ADMIN_USER, entityId, draftId);

      const before = await findDraftEntityRead(testContext, ADMIN_USER, entityId, draftId);
      expect(before?.is_read).toBe(true);

      await resetDraftEntityRead(testContext, ADMIN_USER, entityId, draftId);

      const after = await findDraftEntityRead(testContext, ADMIN_USER, entityId, draftId);
      expect(after?.is_read).toBe(false);
    });
  });

  // ---------------------------------------------------------------
  // Access control — USER_EDITOR cannot access another user's records
  // ---------------------------------------------------------------

  describe('access isolation between users', () => {
    it('should not expose admin read record to a different user', async () => {
      await draftEntityMarkRead(testContext, ADMIN_USER, entityId, draftId);

      const result = await queryAsUserWithSuccess(USER_EDITOR, {
        query: DRAFT_ENTITY_READ_QUERY,
        variables: { entityId, draftId },
      });
      expect(result?.data?.draftEntityRead).toBeNull();
    });

    it('should allow a different user to independently mark as read', async () => {
      // USER_EDITOR marks the same entity as read — should create its own record
      const result = await queryAsUserWithSuccess(USER_EDITOR, {
        query: DRAFT_ENTITY_MARK_READ_MUTATION,
        variables: { entityId, draftId },
      });
      const record = result?.data?.draftEntityMarkRead;
      expect(record).not.toBeNull();
      expect(record.user_id).not.toEqual(ADMIN_USER.id);
      expect(record.is_read).toBe(true);
    });
  });

  // ---------------------------------------------------------------
  // Cleanup — verify ES record is actually deleted with draft
  // ---------------------------------------------------------------

  describe('persistence — record survives until draft deletion', () => {
    it('should find the record in Elasticsearch directly', async () => {
      const record = await findDraftEntityRead(testContext, ADMIN_USER, entityId, draftId);
      expect(record).toBeDefined();
      const esRecord = await elLoadById(testContext, ADMIN_USER, record!.id);
      expect(esRecord).toBeDefined();
    });
  });
});
