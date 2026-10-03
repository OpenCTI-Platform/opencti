import { v5 as uuidv5 } from 'uuid';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cache from '../../../../src/database/cache';
import * as loader from '../../../../src/database/middleware-loader';
import { connectorIdFromWorkId, isOpenAevCoverageConnector, resolveAssertionSource } from '../../../../src/modules/provenance/provenance-source';
import { buildCreationProvenance, removeProvenanceInputs } from '../../../../src/modules/provenance/provenance-write';
import { OPENCTI_NAMESPACE } from '../../../../src/schema/general';
import { RULE_MANAGER_USER } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

const CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c001';
const SHARED_USER_CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c002';
const OPENAEV_CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c003';
const FEED_ID = 'b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1a10';
const FEED_CONNECTOR_ID = uuidv5(FEED_ID, OPENCTI_NAMESPACE);

const connectorUser = { id: 'c0000000-0000-4000-8000-000000000001', name: '[C] AlienVault' } as AuthUser;
const sharedUser = { id: 'c0000000-0000-4000-8000-000000000002', name: 'shared' } as AuthUser;
const humanUser = { id: 'c0000000-0000-4000-8000-000000000003', name: 'Jane Analyst' } as AuthUser;

const connectors = [
  { internal_id: CONNECTOR_ID, name: 'AlienVault', connector_user_id: connectorUser.id },
  { internal_id: SHARED_USER_CONNECTOR_ID, name: 'Shared A', connector_user_id: sharedUser.id },
  { internal_id: 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c004', name: 'Shared B', connector_user_id: sharedUser.id },
  { internal_id: OPENAEV_CONNECTOR_ID, name: 'OpenAEV Coverage', connector_user_id: 'c0000000-0000-4000-8000-000000000005' },
  { internal_id: FEED_CONNECTOR_ID, name: '[FEED - TAXII] Partner collection', connector_user_id: sharedUser.id, built_in: true },
];

const contextFor = (workId?: string) => ({ workId } as AuthContext);
const workOf = (connectorId: string) => `work_${connectorId}_2026-10-03T08:00:00.000Z`;

describe('Provenance source resolution', () => {
  beforeEach(() => {
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue(connectors as never);
    vi.mocked(loader.fullEntitiesList).mockResolvedValue([{ internal_id: FEED_ID, name: 'Partner collection' }] as never);
  });

  it('should read the connector id embedded in a work id', () => {
    expect(connectorIdFromWorkId(workOf(CONNECTOR_ID))).toEqual(CONNECTOR_ID);
    expect(connectorIdFromWorkId(undefined)).toBeNull();
    expect(connectorIdFromWorkId('')).toBeNull();
    expect(connectorIdFromWorkId('not-a-work')).toBeNull();
    expect(connectorIdFromWorkId('work_')).toBeNull();
  });

  it('should detect OpenAEV coverage connectors', () => {
    expect(isOpenAevCoverageConnector({ name: 'OpenAEV Coverage' })).toEqual(true);
    expect(isOpenAevCoverageConnector({ name: 'AlienVault' })).toEqual(false);
  });

  it('should attribute inference engine writes to the rule', async () => {
    const source = await resolveAssertionSource(contextFor(), RULE_MANAGER_USER, {}, { fromRule: 'i_rule_location_targets' });
    expect(source.source_kind).toEqual('inference');
    expect(source.source_id).toEqual('location_targets');
    expect(source.work_id).toBeNull();
  });

  it('should attribute a worker write to the connector of the work', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(CONNECTOR_ID)), sharedUser, {});
    expect(source).toEqual({ source_id: CONNECTOR_ID, source_kind: 'connector', source_name: 'AlienVault', work_id: workOf(CONNECTOR_ID) });
  });

  it('should attribute a direct write to the unique connector of the user', async () => {
    const source = await resolveAssertionSource(contextFor(), connectorUser, { createdBy: { internal_id: 'identity-1', name: 'Vendor' } });
    expect(source.source_kind).toEqual('connector');
    expect(source.source_id).toEqual(CONNECTOR_ID);
  });

  it('should attribute OpenAEV coverage pushes to emulation', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(OPENAEV_CONNECTOR_ID)), humanUser, {});
    expect(source.source_kind).toEqual('emulation');
    expect(source.source_id).toEqual(OPENAEV_CONNECTOR_ID);
  });

  it('should attribute built-in ingestion connectors to the feed', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(FEED_CONNECTOR_ID)), sharedUser, {});
    expect(source).toEqual({ source_id: FEED_ID, source_kind: 'feed', source_name: 'Partner collection', work_id: workOf(FEED_CONNECTOR_ID) });
  });

  it('should attribute a human write with an author to the author', async () => {
    const source = await resolveAssertionSource(contextFor(), humanUser, { createdBy: { internal_id: 'identity-1', name: 'ACME CERT' } });
    expect(source).toEqual({ source_id: 'identity-1', source_kind: 'author', source_name: 'ACME CERT', work_id: null });
  });

  it('should attribute a human write without author to the user', async () => {
    const source = await resolveAssertionSource(contextFor(), humanUser, {});
    expect(source).toEqual({ source_id: humanUser.id, source_kind: 'user', source_name: 'Jane Analyst', work_id: null });
  });

  it('should not guess between several connectors sharing a user', async () => {
    const source = await resolveAssertionSource(contextFor(), sharedUser, {});
    expect(source.source_kind).toEqual('user');
    expect(source.source_id).toEqual(sharedUser.id);
  });
});

describe('Provenance write helpers', () => {
  it('should never accept provenance from client inputs', () => {
    const input = removeProvenanceInputs({
      name: 'APT29',
      x_opencti_assertions: [{ source_id: 'forged' }],
      corroboration_count: 99,
      single_sourced: false,
      has_conflicts: true,
      x_opencti_conflicts: [],
      procedures: [{ text: 'forged' }],
      freshness_stale: true,
    });
    expect(input).toEqual({ name: 'APT29' });
  });

  it('should build the provenance of a created element', () => {
    const at = '2026-10-03T08:00:00.000Z';
    const source = { source_id: CONNECTOR_ID, source_kind: 'connector' as const, source_name: 'AlienVault', work_id: null };
    expect(buildCreationProvenance(source, 75, at)).toEqual({
      x_opencti_assertions: [{
        source_id: CONNECTOR_ID,
        source_kind: 'connector',
        source_name: 'AlienVault',
        first_asserted_at: at,
        last_asserted_at: at,
        assert_count: 1,
        confidence: 75,
        work_id: null,
      }],
      assertion_source_ids: [CONNECTOR_ID],
      assertion_source_kinds: ['connector'],
      corroboration_count: 1,
      last_asserted_at: at,
      single_sourced: true,
      has_conflicts: false,
    });
  });
});
