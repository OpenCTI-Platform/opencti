import gql from 'graphql-tag';
import { LRUCache } from 'lru-cache';
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, adminQuery, testContext } from '../utils/testQuery';
import { stixRefsExtractor } from '../../src/schema/stixEmbeddedRelationship';
import { resolveMissingReferences } from '../../src/graphql/sseMiddleware';
import { convertStoreToStix_2_1 } from '../../src/database/stix-2-1-converter';
import { storeLoadByIdWithRefs } from '../../src/database/middleware';
import { adminQueryWithSuccess } from '../utils/testQueryHelper';
import type { StoreObject } from '../../src/types/store';

const CREATE_REPORT_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
      standard_id
      name
      description
      published
      objects {
        edges {
          node {
            ... on StixCoreObject {
              id
              standard_id
            }
          }
        }
      }
    }
  }
`;

const CREATE_CASE_QUERY = gql`
  mutation CaseIncidentAdd($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input){
      id
      standard_id
      name
      description
      objects {
        edges {
          node {
            ... on StixCoreObject {
              id
              standard_id
            }
          }
        }
      }
    }
  }
`;

const DELETE_DOMAIN_QUERY = gql`
  mutation stixDomainObjectDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) {
      delete
    }
  }
`;

describe('Should stream parent resolutions correctly working', () => {
  it('should recursive resolution working as expected', async () => {
    // REPORT 01 -- ref --> CASE 01 -- ref --> CASE 02 -- ref --> REPORT 01
    // CASE 01
    const case01Resolution = await adminQueryWithSuccess({
      query: CREATE_CASE_QUERY,
      variables: {
        input: {
          name: 'Case-01-Resolution',
        },
      },
    });
    // REPORT 01
    const case01ResolutionId = case01Resolution.data.caseIncidentAdd.id;
    const report01Resolution = await adminQueryWithSuccess({
      query: CREATE_REPORT_QUERY,
      variables: {
        input: {
          name: 'Report-01-Resolution',
          description: 'Report-01-Resolution',
          published: '2020-02-26T00:51:35.000Z',
          objects: [case01ResolutionId],
        },
      },
    });
    // CREATE CASE 02
    const report01ResolutionId = report01Resolution.data.reportAdd.id;
    const case02Resolution = await adminQueryWithSuccess({
      query: CREATE_CASE_QUERY,
      variables: {
        input: {
          name: 'Case-02-Resolution',
          objects: [report01ResolutionId],
        },
      },
    });
    // ADD CASE02 in CASE01 via upsert
    const case02ResolutionId = case02Resolution.data.caseIncidentAdd.id;
    await adminQueryWithSuccess({
      query: CREATE_CASE_QUERY,
      variables: {
        input: {
          stix_id: case01Resolution.data.caseIncidentAdd.standard_id,
          name: 'Case-01-Resolution',
          objects: [case02ResolutionId],
        },
      },
    });
    const reportWithRefs = await storeLoadByIdWithRefs(testContext, ADMIN_USER, report01ResolutionId);
    const stixReport = convertStoreToStix_2_1(reportWithRefs as StoreObject);
    const refs = stixRefsExtractor(stixReport);
    const cache = new LRUCache({ max: 5000, ttl: 1000 * 60 * 60 });
    const missingInstances: any[] = await resolveMissingReferences(testContext, ADMIN_USER, refs, cache);
    expect(missingInstances.length).toBe(4);
    // REPORT01
    expect(missingInstances[0].stix.id).toBe('report--b8c1e232-cfa4-5fe9-b7cc-b631b46d4424');
    expect(missingInstances[0].stix.name).toBe('Report-01-Resolution');
    // INDIVIDUAL (auto created)
    expect(missingInstances[1].stix.id).toBe('identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91');
    expect(missingInstances[1].stix.name).toBe('admin');
    expect(missingInstances[1].message).toBe('creates a Individual `admin`');
    // CASE02
    expect(missingInstances[2].stix.name).toBe('Case-02-Resolution');
    expect(missingInstances[2].message).toBe('creates a Case-Incident `Case-02-Resolution`');
    // CASE01
    expect(missingInstances[3].stix.name).toBe('Case-01-Resolution');
    expect(missingInstances[3].message).toBe('creates a Case-Incident `Case-01-Resolution`');
    // CLEANUP
    await adminQuery({ query: DELETE_DOMAIN_QUERY, variables: { id: case02ResolutionId } });
    await adminQuery({ query: DELETE_DOMAIN_QUERY, variables: { id: case01ResolutionId } });
    await adminQuery({ query: DELETE_DOMAIN_QUERY, variables: { id: report01ResolutionId } });
  });
});
