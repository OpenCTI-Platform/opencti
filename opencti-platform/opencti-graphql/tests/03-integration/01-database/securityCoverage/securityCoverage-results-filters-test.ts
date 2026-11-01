import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addSecurityCoverage, findById, findResultsRelationshipsPaginated, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { addSecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import type { BasicStoreEntitySecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { addStixCoreRelationship, findStixCoreRelationshipsPaginated } from '../../../../src/domain/stixCoreRelationship';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../src/schema/stixDomainObject';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import type { StoreEntityReport } from '../../../../src/types/store';

type CoverageEntry = { coverage_name: string; coverage_score: number };

describe('Security coverage results: filters on coverage_information', () => {
  const adminContext = { ...testContext, user: ADMIN_USER };
  let report: StoreEntityReport;
  let securityCoverage: BasicStoreEntitySecurityCoverage;
  let resultA: { id: string };
  let resultB: { id: string };
  const attackPatternIds: string[] = [];
  // relationship id -> label (r1...)
  const labels = new Map<string, string>();
  const relationshipIds: Record<string, string> = {};
  const targetIds: Record<string, string> = {};

  const createHasCovered = async (label: string, from: { id: string }, toName: string, coverage?: CoverageEntry[]) => {
    const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: `Tested ${toName}` });
    attackPatternIds.push(attackPattern.id);
    targetIds[toName] = attackPattern.id;
    const relationship = await addStixCoreRelationship(testContext, ADMIN_USER, {
      fromId: from.id,
      toId: attackPattern.id,
      relationship_type: 'has-covered',
      ...(coverage ? { coverage_information: coverage } : {}),
    });
    labels.set(relationship.id, label);
    relationshipIds[label] = relationship.id;
  };

  const rels = async (filters: object, extraArgs: object = {}) => {
    const result = await findResultsRelationshipsPaginated(testContext, ADMIN_USER, securityCoverage, { filters, ...extraArgs } as any);
    return result.edges.map((edge) => labels.get(edge.node.id) as string).sort();
  };
  const coverage = (values: object[], operator = 'eq') => ({ mode: 'and', filterGroups: [], filters: [{ key: ['coverage_information'], operator, mode: 'and', values }] });
  const name = (operator: string, ...values: string[]) => ({ key: 'coverage_name', operator, values });
  const score = (operator: string, value: string) => ({ key: 'coverage_score', operator, values: [value] });

  beforeAll(async () => {
    report = await addReport(testContext, ADMIN_USER, { name: 'Report for SCR filters tests', published: '2026-04-24T19:15:00.000Z' });
    const created = await addSecurityCoverage(adminContext, ADMIN_USER, { name: 'sc filters', objectCovered: report.standard_id, auto_enrichment_disable: true });
    resultA = await addSecurityCoverageResult(adminContext, ADMIN_USER, { name: 'OAEV kilo', resultOf: created.id });
    resultB = await addSecurityCoverageResult(adminContext, ADMIN_USER, { name: 'OAEV lima', resultOf: created.id });
    await createHasCovered('r1', resultA, 'alpha', [{ coverage_name: 'detection', coverage_score: 10 }, { coverage_name: 'prevention', coverage_score: 90 }]);
    await createHasCovered('r2', resultA, 'bravo', [{ coverage_name: 'detection', coverage_score: 90 }, { coverage_name: 'prevention', coverage_score: 10 }]);
    await createHasCovered('r3', resultB, 'charlie', [{ coverage_name: 'detection', coverage_score: 0 }]);
    await createHasCovered('r4', resultB, 'delta', [{ coverage_name: 'prevention', coverage_score: 12 }]);
    // An empty coverage_information list is stored as an absent one (both load as []): r5 covers both cases
    await createHasCovered('r5', resultB, 'echo');
    securityCoverage = await findById(adminContext, ADMIN_USER, created.id);
  });

  afterAll(async () => {
    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    for (const id of attackPatternIds) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, id, ENTITY_TYPE_ATTACK_PATTERN);
    }
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
  });

  it('filters on name and score of the same entry', async () => {
    expect(await rels(coverage([name('eq', 'detection'), score('lt', '20')]))).toEqual(['r1', 'r3']);
    expect(await rels(coverage([name('eq', 'detection'), score('gte', '90')]))).toEqual(['r2']);
  });
  it('does not match name and score on two different entries', async () => {
    // r2 has detection 90 and prevention 10: no detection entry below 20
    expect(await rels(coverage([name('eq', 'detection'), score('lt', '20')]))).not.toContain('r2');
  });
  it('filters on the score of any entry', async () => {
    expect(await rels(coverage([score('lt', '12.5')]))).toEqual(['r1', 'r2', 'r3', 'r4']);
    expect(await rels(coverage([score('eq', '0')]))).toEqual(['r3']);
  });
  it('filters with not_eq on the name and OR on several names', async () => {
    expect(await rels(coverage([name('not_eq', 'detection'), score('lt', '20')]))).toEqual(['r2', 'r4']);
    expect(await rels(coverage([name('eq', 'detection', 'prevention'), score('gte', '90')]))).toEqual(['r1', 'r2']);
  });
  it('filters relationships with no coverage or with some', async () => {
    expect(await rels(coverage([], 'nil'))).toEqual(['r5']);
    expect(await rels(coverage([], 'not_nil'))).toEqual(['r1', 'r2', 'r3', 'r4']);
  });
  it('rejects an invalid sub-filter key or operator', async () => {
    await expect(rels(coverage([{ key: 'unknown', values: ['a'] }]))).rejects.toThrow();
    await expect(rels(coverage([score('not_eq', '20')]))).rejects.toThrow();
  });
  it('combines with fromId, toTypes, updated_at and search', async () => {
    const lowScore = coverage([score('lt', '20')]).filters;
    const withFilters = (...filters: object[]) => ({ mode: 'and', filterGroups: [], filters: [...lowScore, ...filters] });
    const fromB = { key: ['fromId'], values: [resultB.id] };
    const toAttackPattern = { key: ['toTypes'], values: ['Attack-Pattern'] };
    const recent = { key: ['updated_at'], operator: 'within', values: ['now-7d', 'now'] };
    expect(await rels(withFilters(fromB))).toEqual(['r3', 'r4']);
    expect(await rels(withFilters(fromB, toAttackPattern))).toEqual(['r3', 'r4']);
    expect(await rels(withFilters(fromB, toAttackPattern, recent))).toEqual(['r3', 'r4']);
    expect(await rels(withFilters(fromB, toAttackPattern, recent, { key: ['toId'], values: [targetIds.charlie] }))).toEqual(['r3']);
    const noFilters = { mode: 'and', filterGroups: [], filters: [] };
    expect(await rels(noFilters, { search: 'charlie' })).toEqual(['r3']);
    expect(await rels(noFilters, { search: 'kilo' })).toEqual(['r1', 'r2']);
  });
  it('returns no row and no error when the relationship type cannot carry the key', async () => {
    const result = await findStixCoreRelationshipsPaginated(testContext, ADMIN_USER, { relationship_type: ['uses'], filters: coverage([score('lt', '20')]) });
    expect(result.edges).toEqual([]);
  });
});
