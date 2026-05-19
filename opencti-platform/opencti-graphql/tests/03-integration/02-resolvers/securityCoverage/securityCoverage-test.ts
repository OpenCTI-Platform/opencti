import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
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
    expect(securityCoverageData.external_uri).toEqual('http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a175');
    expect(securityCoverageData.coverage_information[0].coverage_name).toEqual('prevention');
    expect(securityCoverageData.coverage_information[0].coverage_score).toEqual(10);
  });
});
