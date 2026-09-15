import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../../utils/testQueryHelper';

const CREATE_QUERY = gql`
 mutation SecurityCoverageAdd($input: SecurityCoverageAddInput!) {
    securityCoverageAdd(input: $input) {
      name
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
      external_uri
    }
  }
`;

describe('SecurityCoverage resolver', () => {
  it('should create SecurityCoverage with correct coverage information', async () => {
    const SECURITY_COVERAGE = {
      input: {
        name: 'SC name',
        objectCovered: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
        auto_enrichment_disable: true,
        coverage_last_result: '2023-08-06T11:39:36.949Z',
        coverage_valid_from: '2023-07-06T11:39:36.949Z',
        coverage_valid_to: '2023-12-06T11:39:36.949Z',
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a175',
      },
    };

    const securityCoverage = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: SECURITY_COVERAGE,
    });

    const securityCoverageData = securityCoverage.data?.securityCoverageAdd;
    expect(securityCoverageData).toBeDefined();
    expect(securityCoverageData.name).toEqual('SC name');
    expect(securityCoverageData.coverage_last_result.toISOString()).toEqual('2023-08-06T11:39:36.949Z');
    expect(securityCoverageData.coverage_valid_from.toISOString()).toEqual('2023-07-06T11:39:36.949Z');
    expect(securityCoverageData.coverage_valid_to.toISOString()).toEqual('2023-12-06T11:39:36.949Z');
    expect(securityCoverageData.coverage_information[0].coverage_name).toEqual('prevention');
    expect(securityCoverageData.coverage_information[0].coverage_score).toEqual(10);
  });
});

const MALWARE_ADD = gql`
  mutation MalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) { id }
  }
`;
const ATTACK_PATTERN_ADD = gql`
  mutation AttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) { id standard_id name }
  }
`;
const VULNERABILITY_ADD = gql`
  mutation VulnerabilityAdd($input: VulnerabilityAddInput!) {
    vulnerabilityAdd(input: $input) { id standard_id name }
  }
`;
const SECURITY_COVERAGE_ADD = gql`
  mutation SecurityCoverageAdd($input: SecurityCoverageAddInput!) {
    securityCoverageAdd(input: $input) { id }
  }
`;
const SECURITY_COVERAGE_RESULT_ADD = gql`
  mutation SecurityCoverageResultAdd($input: SecurityCoverageResultAddInput!) {
    securityCoverageResultAdd(input: $input) { id }
  }
`;
const HAS_COVERED_ADD = gql`
  mutation HasCoveredAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id }
  }
`;
const COVERED_ENTITIES_QUERY = gql`
  query CoveredEntities($id: String!) {
    securityCoverage(id: $id) {
      coveredAttackPatterns(first: 100) {
        count
        entities {
          relationship_id
          coverage_information { coverage_name coverage_score }
          to { id name }
        }
      }
      coveredVulnerabilities(first: 100) {
        count
        entities {
          relationship_id
          to { id name }
        }
      }
    }
  }
`;
const RESULTS_RELATIONSHIPS_QUERY = gql`
  query ResultsRelationships($id: String!) {
    securityCoverage(id: $id) {
      coveredEntitiesDistribution(field: "entity_type", relationship_type: ["has-covered"], operation: count) {
        label
        value
      }
      stixCoreRelationshipsFromResults(first: 100, relationship_type: "has-covered") {
        pageInfo { globalCount }
      }
      coveredAttackPatterns(first: 100) { count }
      coveredVulnerabilities(first: 100) { count }
    }
  }
`;
const GENERIC_DELETE = gql`
  mutation GenericDelete($id: ID!) {
    stixCoreObjectEdit(id: $id) { delete }
  }
`;
const SECURITY_COVERAGE_RESULT_DELETE = gql`
  mutation SecurityCoverageResultDelete($id: ID!) {
    securityCoverageResultDelete(id: $id)
  }
`;
const SECURITY_COVERAGE_DELETE = gql`
  mutation SecurityCoverageDelete($id: ID!) {
    securityCoverageDelete(id: $id)
  }
`;

describe('SecurityCoverage covered entities resolvers', () => {
  let coverageId: string;
  let resultId: string;
  let malwareId: string;
  let malwareWithoutResultId: string;
  let attackPatternId: string;
  let vulnerabilityId: string;
  let attackPatternRelId: string;
  let vulnerabilityRelId: string;
  let coverageWithoutResultId: string;

  beforeAll(async () => {
    malwareId = (await queryAsAdmin({
      query: MALWARE_ADD,
      variables: { input: { name: 'SC covered-entities malware' } },
    })).data?.malwareAdd.id;
    malwareWithoutResultId = (await queryAsAdmin({
      query: MALWARE_ADD,
      variables: { input: { name: 'SC covered-entities malware without result' } },
    })).data?.malwareAdd.id;
    attackPatternId = (await queryAsAdmin({
      query: ATTACK_PATTERN_ADD,
      variables: { input: { name: 'SC covered attack pattern' } },
    })).data?.attackPatternAdd.id;
    vulnerabilityId = (await queryAsAdmin({
      query: VULNERABILITY_ADD,
      variables: { input: { name: 'SC covered vulnerability' } },
    })).data?.vulnerabilityAdd.id;
    coverageId = (await queryAsAdmin({
      query: SECURITY_COVERAGE_ADD,
      variables: { input: { name: 'SC covered-entities coverage', objectCovered: malwareId, auto_enrichment_disable: true } },
    })).data?.securityCoverageAdd.id;
    resultId = (await queryAsAdmin({
      query: SECURITY_COVERAGE_RESULT_ADD,
      variables: { input: { name: 'SC covered-entities result', resultOf: coverageId } },
    })).data?.securityCoverageResultAdd.id;

    attackPatternRelId = (await queryAsAdmin({
      query: HAS_COVERED_ADD,
      variables: { input: { fromId: resultId, toId: attackPatternId, relationship_type: 'has-covered', coverage_information: [{ coverage_name: 'detection', coverage_score: 42 }] } },
    })).data?.stixCoreRelationshipAdd.id;
    vulnerabilityRelId = (await queryAsAdmin({
      query: HAS_COVERED_ADD,
      variables: { input: { fromId: resultId, toId: vulnerabilityId, relationship_type: 'has-covered', coverage_information: [{ coverage_name: 'detection', coverage_score: 7 }] } },
    })).data?.stixCoreRelationshipAdd.id;

    coverageWithoutResultId = (await queryAsAdmin({
      query: SECURITY_COVERAGE_ADD,
      variables: { input: { name: 'SC covered-entities coverage without result', objectCovered: malwareWithoutResultId, auto_enrichment_disable: true } },
    })).data?.securityCoverageAdd.id;
  });

  afterAll(async () => {
    for (const id of [attackPatternId, vulnerabilityId]) {
      if (id) await queryAsAdmin({ query: GENERIC_DELETE, variables: { id } });
    }
    if (resultId) await queryAsAdmin({ query: SECURITY_COVERAGE_RESULT_DELETE, variables: { id: resultId } });
    if (coverageId) await queryAsAdmin({ query: SECURITY_COVERAGE_DELETE, variables: { id: coverageId } });
    if (coverageWithoutResultId) await queryAsAdmin({ query: SECURITY_COVERAGE_DELETE, variables: { id: coverageWithoutResultId } });
    for (const id of [malwareId, malwareWithoutResultId]) {
      if (id) await queryAsAdmin({ query: GENERIC_DELETE, variables: { id } });
    }
  });

  it('should return covered attack patterns with concrete node and relationship_id', async () => {
    const { data } = await queryAsAdmin({ query: COVERED_ENTITIES_QUERY, variables: { id: coverageId } });
    const attackPatterns = data?.securityCoverage.coveredAttackPatterns;
    expect(attackPatterns.count).toEqual(1);
    expect(attackPatterns.entities).toHaveLength(1);
    const [entity] = attackPatterns.entities;
    expect(entity.relationship_id).toEqual(attackPatternRelId);
    expect(entity.to.id).toEqual(attackPatternId);
    expect(entity.to.name).toEqual('SC covered attack pattern');
    expect(entity.coverage_information[0].coverage_name).toEqual('detection');
    expect(entity.coverage_information[0].coverage_score).toEqual(42);
  });

  it('should return covered vulnerabilities filtered by their concrete type', async () => {
    const { data } = await queryAsAdmin({ query: COVERED_ENTITIES_QUERY, variables: { id: coverageId } });
    const vulnerabilities = data?.securityCoverage.coveredVulnerabilities;
    expect(vulnerabilities.count).toEqual(1);
    expect(vulnerabilities.entities).toHaveLength(1);
    const [entity] = vulnerabilities.entities;
    expect(entity.relationship_id).toEqual(vulnerabilityRelId);
    expect(entity.to.id).toEqual(vulnerabilityId);
  });

  it('should return the has-covered relationships of a coverage that has a result', async () => {
    const { data } = await queryAsAdmin({ query: RESULTS_RELATIONSHIPS_QUERY, variables: { id: coverageId } });
    const coverage = data?.securityCoverage;
    expect(coverage.stixCoreRelationshipsFromResults.pageInfo.globalCount).toEqual(2);
    expect(coverage.coveredAttackPatterns.count).toEqual(1);
    expect(coverage.coveredVulnerabilities.count).toEqual(1);
    const distributionTotal = coverage.coveredEntitiesDistribution.reduce((sum: number, d: { value: number }) => sum + d.value, 0);
    expect(distributionTotal).toEqual(2);
  });

  it('should return no has-covered relationship for a coverage without result', async () => {
    const { data } = await queryAsAdmin({ query: RESULTS_RELATIONSHIPS_QUERY, variables: { id: coverageWithoutResultId } });
    const coverage = data?.securityCoverage;
    expect(coverage.stixCoreRelationshipsFromResults.pageInfo.globalCount).toEqual(0);
    expect(coverage.coveredAttackPatterns.count).toEqual(0);
    expect(coverage.coveredVulnerabilities.count).toEqual(0);
    expect(coverage.coveredEntitiesDistribution).toEqual([]);
  });
});
// endregion
