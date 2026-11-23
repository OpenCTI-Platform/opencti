import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { testContext } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { FilterMode, PirType } from '../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById, pageRelationsConnection } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import type { BasicStoreEntity } from '../../../src/types/store';
import { resetCacheForEntity } from '../../../src/database/cache';
import { type BasicStoreRelationPir, ENTITY_TYPE_PIR } from '../../../src/modules/pir/pir-types';
import { RELATION_IN_PIR } from '../../../src/schema/internalRelationship';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT } from '../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';
import { listMatches } from '../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-domain';
import { loadRequirementOfPirMap, migratePirsToRequirements } from '../../../src/modules/intelligenceRequirement/intelligenceRequirement-pirMigration';

// Migration 1795536000000 (opencti #20278): every Pir becomes an intelligence requirement with its flags and scores unchanged,
// then the Pir is deleted. Run twice to prove it is idempotent.

const CREATE_QUERY = gql`
  mutation PirMigrationAdd($input: PirAddInput!) {
    pirAdd(input: $input) { id name }
  }
`;

const FLAG_QUERY = gql`
  mutation PirMigrationFlag($id: ID!, $input: PirFlagElementInput!) {
    pirFlagElement(id: $id, input: $input)
  }
`;

const DELETE_REQUIREMENT_QUERY = gql`
  mutation PirMigrationRequirementDelete($id: ID!) {
    intelligenceRequirementDelete(id: $id)
  }
`;

const MALWARE_STIX_ID = 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88';
const AUTHOR_STIX_ID = 'identity--732421a0-8471-52de-8d9f-18c8b260813c';
const CRITERION_A = 'd17360d5-0b58-4a21-bebc-84aa5a3f32b4';
const CRITERION_B = '527e5e30-02c5-4ba9-a698-45954d1f3763';

const criterionFilters = (toId: string) => ({ mode: FilterMode.And, filterGroups: [], filters: [{ key: ['toId'], values: [toId] }] });

describe('Pir migration to intelligence requirements', () => {
  let pirId = '';
  let malwareId = '';
  let requirementId = '';

  beforeAll(async () => {
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    const malware = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, MALWARE_STIX_ID, { type: ENTITY_TYPE_MALWARE });
    malwareId = malware.id;
    const author = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, AUTHOR_STIX_ID, { type: ENTITY_TYPE_IDENTITY_ORGANIZATION });
    const created = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: {
        input: {
          name: 'Pir to migrate',
          pir_type: PirType.ThreatLandscape,
          pir_rescan_days: 0,
          pir_filters: { mode: FilterMode.And, filterGroups: [], filters: [] },
          pir_criteria: [
            { weight: 1, filters: criterionFilters(CRITERION_A) },
            { weight: 1, filters: criterionFilters(CRITERION_B) },
          ],
        },
      },
    });
    pirId = created.data.pirAdd.id;
    resetCacheForEntity(ENTITY_TYPE_PIR);
    // one legacy flag on the malware, on the first criterion: score 50
    await queryAsAdminWithSuccess({
      query: FLAG_QUERY,
      variables: {
        id: pirId,
        input: {
          relationshipId: 'migration-relationship',
          sourceId: malwareId,
          matchingCriteria: [{ weight: 1, filters: criterionFilters(CRITERION_A) }],
          relationshipAuthorId: author.id,
        },
      },
    });
  });

  afterAll(async () => {
    if (requirementId) await queryAsAdmin({ query: DELETE_REQUIREMENT_QUERY, variables: { id: requirementId } });
    resetCacheForEntity(ENTITY_TYPE_PIR);
  });

  it('should hold one flag of score 50 before the migration', async () => {
    const flags = await pageRelationsConnection<BasicStoreRelationPir>(testContext, SYSTEM_USER, RELATION_IN_PIR, { toId: [pirId] });
    expect(flags.edges.length).toEqual(1);
    expect(flags.edges[0].node.pir_score).toEqual(50);
  });

  it('should convert the Pir into an active requirement with the same entity and score, then delete the Pir', async () => {
    const report = await migratePirsToRequirements(testContext);
    expect(report.pirs).toBeGreaterThanOrEqual(1);
    expect(report.converted).toBeGreaterThanOrEqual(1);
    expect(report.failed.map((f) => f.pir_id)).not.toContain(pirId);
    expect(report.playbooks).toBeGreaterThanOrEqual(report.playbooks_rewritten);
    // the requirement of the Pir is found by ir_pir_id once the Pir is gone
    const requirementOfPir = await loadRequirementOfPirMap(testContext);
    requirementId = requirementOfPir.get(pirId) ?? '';
    expect(requirementId).toBeTruthy();
    const requirement = await internalLoadById<BasicStoreEntityIntelligenceRequirement>(testContext, SYSTEM_USER, requirementId, { type: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT });
    expect(requirement.ir_status).toEqual('active');
    expect(requirement.name).toEqual('Pir to migrate');
    const matches = await listMatches(testContext, SYSTEM_USER, requirementId);
    expect(matches.length).toEqual(1);
    expect(matches[0].match_entity_id).toEqual(malwareId);
    expect(matches[0].match_status).toEqual('auto');
    expect(matches[0].match_score).toEqual(50);
    // the Pir, its flags and the legacy trace on the entity are gone
    resetCacheForEntity(ENTITY_TYPE_PIR);
    const pir = await internalLoadById(testContext, SYSTEM_USER, pirId, { type: ENTITY_TYPE_PIR });
    expect(pir).toBeFalsy();
    const flags = await pageRelationsConnection<BasicStoreRelationPir>(testContext, SYSTEM_USER, RELATION_IN_PIR, { toId: [pirId] });
    expect(flags.edges.length).toEqual(0);
    const malware = await internalLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, malwareId, { type: ENTITY_TYPE_MALWARE });
    expect((malware.pir_information ?? []).filter((info) => info.pir_id === pirId)).toEqual([]);
  });

  it('should be idempotent: a second run converts nothing new and keeps the entity of the requirement', async () => {
    const report = await migratePirsToRequirements(testContext);
    expect(report.failed.map((f) => f.pir_id)).not.toContain(pirId);
    const matches = await listMatches(testContext, SYSTEM_USER, requirementId);
    expect(matches.length).toEqual(1);
    expect(matches[0].match_score).toEqual(50);
  });
});
