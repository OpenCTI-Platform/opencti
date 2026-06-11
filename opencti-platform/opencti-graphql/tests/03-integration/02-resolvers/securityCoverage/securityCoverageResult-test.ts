import gql from 'graphql-tag';
import { beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../../utils/testQueryHelper';

const GET_SECURITY_COVERAGES = gql`
 query SecurityCoverages {
    securityCoverages {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const GET_ALL_QUERY = gql`
 query SecurityCoverageResults {
    securityCoverageResults {
      pageInfo {
        globalCount
      }
      edges {
        node {
          external_uri
          coverage_last_result
          coverage_valid_from
          coverage_valid_to
          coverage_information {
            coverage_name
            coverage_score
          }
        }
      }
    }
  }
`;

const GET_ALL_BY_ID_QUERY = gql`
 query SecurityCoverageResultById($id: String!) {
    listSecurityCoverageResultsByResultOf(id: $id) {
      external_uri
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
    }
  }
`;

const GET_ONE_QUERY = gql`
 query SecurityCoverageResult($id: String!) {
    securityCoverageResult(id: $id) {
      external_uri
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
    }
  }
`;

const CREATE_MUTATION = gql`
  mutation CreateSecurityCoverageResult($input: SecurityCoverageResultAddInput!) {
    securityCoverageResultAdd(input: $input) {
      id
      external_uri
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
    }
  }
`;

const DELETE_MUTATION = gql`
  mutation DeleteSecurityCoverageResult($id: ID!) {
    securityCoverageResultDelete(id: $id)
  }
`;

describe('SecurityCoverageResult resolver', () => {
  let securityCoverageId: string;
  let createdScrId: string;

  beforeAll(async () => {
    const { data } = await queryAsAdmin({ query: GET_SECURITY_COVERAGES });
    securityCoverageId = data?.securityCoverages.edges[0].node.id;
  });

  it('should create a new result for a security coverage', async () => {
    const scr = await queryAsAdmin({
      query: CREATE_MUTATION,
      variables: {
        input: {
          resultOf: securityCoverageId,
          coverage_last_result: '2025-08-06T11:39:36.949Z',
          coverage_valid_from: '2025-07-06T11:39:36.949Z',
          coverage_valid_to: '2026-12-06T11:39:36.949Z',
          coverage_information: [{
            coverage_name: 'vulnerability',
            coverage_score: 50,
          }],
          external_uri: 'http://localhost/admin/scenarios/d49dd003-3498-441f-96a8-a533067b1322',
        },
      },
    });

    const securityCoverageResultData = scr.data?.securityCoverageResultAdd;
    expect(securityCoverageResultData).toBeDefined();
    expect(securityCoverageResultData.coverage_last_result.toISOString()).toEqual('2025-08-06T11:39:36.949Z');
    expect(securityCoverageResultData.coverage_valid_from.toISOString()).toEqual('2025-07-06T11:39:36.949Z');
    expect(securityCoverageResultData.coverage_valid_to.toISOString()).toEqual('2026-12-06T11:39:36.949Z');
    expect(securityCoverageResultData.external_uri).toEqual('http://localhost/admin/scenarios/d49dd003-3498-441f-96a8-a533067b1322');
    expect(securityCoverageResultData.coverage_information[0].coverage_name).toEqual('vulnerability');
    expect(securityCoverageResultData.coverage_information[0].coverage_score).toEqual(50);
    createdScrId = securityCoverageResultData.id;
  });

  it('should fetch all security coverage results with pagination', async () => {
    const securityCoverageResults = await queryAsAdmin({
      query: GET_ALL_QUERY,
    });

    const securityCoverageResultsData = securityCoverageResults.data?.securityCoverageResults;
    expect(securityCoverageResultsData).toBeDefined();
    expect(securityCoverageResultsData.pageInfo.globalCount).toEqual(2);
    const uris = securityCoverageResultsData.edges.map((e: any) => e.node.external_uri);
    expect(uris).toContain('http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a175');
    expect(uris).toContain('http://localhost/admin/scenarios/d49dd003-3498-441f-96a8-a533067b1322');
  });

  it('should fetch all results by security coverage ID', async () => {
    const securityCoverageResults = await queryAsAdmin({
      query: GET_ALL_BY_ID_QUERY,
      variables: {
        id: securityCoverageId,
      },
    });

    const securityCoverageResultsData = securityCoverageResults.data?.listSecurityCoverageResultsByResultOf;
    expect(securityCoverageResultsData).toBeDefined();
    expect(securityCoverageResultsData.length).toEqual(2);
    const uris = securityCoverageResultsData.map((scr: any) => scr.external_uri);
    expect(uris).toContain('http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a175');
    expect(uris).toContain('http://localhost/admin/scenarios/d49dd003-3498-441f-96a8-a533067b1322');
  });

  it('should fetch a security coverage result by its ID', async () => {
    const scr = await queryAsAdmin({
      query: GET_ONE_QUERY,
      variables: {
        id: createdScrId,
      },
    });

    const securityCoverageResultData = scr.data?.securityCoverageResult;
    expect(securityCoverageResultData).toBeDefined();
    expect(securityCoverageResultData.coverage_last_result.toISOString()).toEqual('2025-08-06T11:39:36.949Z');
    expect(securityCoverageResultData.coverage_valid_from.toISOString()).toEqual('2025-07-06T11:39:36.949Z');
    expect(securityCoverageResultData.coverage_valid_to.toISOString()).toEqual('2026-12-06T11:39:36.949Z');
    expect(securityCoverageResultData.external_uri).toEqual('http://localhost/admin/scenarios/d49dd003-3498-441f-96a8-a533067b1322');
    expect(securityCoverageResultData.coverage_information[0].coverage_name).toEqual('vulnerability');
    expect(securityCoverageResultData.coverage_information[0].coverage_score).toEqual(50);
  });

  it('should delete a security coverage result by its ID', async () => {
    const result = await queryAsAdmin({
      query: DELETE_MUTATION,
      variables: {
        id: createdScrId,
      },
    });
    const securityCoverageResults = await queryAsAdmin({
      query: GET_ALL_QUERY,
    });

    const deletedId = result.data?.securityCoverageResultDelete;
    const securityCoverageResultsData = securityCoverageResults.data?.securityCoverageResults;
    expect(securityCoverageResultsData.pageInfo.globalCount).toEqual(1);
    expect(deletedId).toEqual(createdScrId);
  });
});
