import gql from 'graphql-tag';
import { LRUCache } from 'lru-cache';
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../utils/testQuery';
import { queryAsAdmin } from '../utils/testQueryHelper';
import { stixRefsExtractor } from '../../src/schema/stixEmbeddedRelationship';
import { resolveMissingReferences } from '../../src/graphql/sseMiddleware';
import { convertStoreToStix_2_1 } from '../../src/database/stix-2-1-converter';
import { storeLoadByIdWithRefs } from '../../src/database/middleware';
import { queryAsAdminWithSuccess } from '../utils/testQueryHelper';
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
    const case01Resolution = await queryAsAdminWithSuccess({
      query: CREATE_CASE_QUERY,
      variables: {
        input: {
          name: 'Case-01-Resolution',
        },
      },
    });
    // REPORT 01
    const case01ResolutionId = case01Resolution.data.caseIncidentAdd.id;
    const report01Resolution = await queryAsAdminWithSuccess({
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
    const case02Resolution = await queryAsAdminWithSuccess({
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
    await queryAsAdminWithSuccess({
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
    const missingInstances: any[] = [];
    const isComplete = await resolveMissingReferences(testContext, ADMIN_USER, refs, cache, (resolved: any[]) => {
      missingInstances.push(...resolved);
    });
    expect(isComplete).toBe(true);
    expect(missingInstances.length).toBe(4);
    const indexOf = (name: string) => missingInstances.findIndex((instance) => instance.stix.name === name);
    // REPORT01
    const report01 = missingInstances[indexOf('Report-01-Resolution')];
    expect(report01.stix.id).toBe('report--b8c1e232-cfa4-5fe9-b7cc-b631b46d4424');
    // INDIVIDUAL (auto created)
    const individual = missingInstances[indexOf('admin')];
    expect(individual.stix.id).toBe('identity--cfb1de38-c40a-5f51-81f3-35036a4e3b91');
    expect(individual.message).toBe('creates a Individual `admin`');
    // CASE02
    expect(missingInstances[indexOf('Case-02-Resolution')].message).toBe('creates a Case-Incident `Case-02-Resolution`');
    // CASE01
    expect(missingInstances[indexOf('Case-01-Resolution')].message).toBe('creates a Case-Incident `Case-01-Resolution`');
    // Dependencies first: CASE01 needs CASE02, which needs REPORT01 (the cycle is closed by the report itself)
    expect(indexOf('Report-01-Resolution')).toBeLessThan(indexOf('Case-02-Resolution'));
    expect(indexOf('Case-02-Resolution')).toBeLessThan(indexOf('Case-01-Resolution'));
    // CLEANUP
    await queryAsAdmin({ query: DELETE_DOMAIN_QUERY, variables: { id: case02ResolutionId } });
    await queryAsAdmin({ query: DELETE_DOMAIN_QUERY, variables: { id: case01ResolutionId } });
    await queryAsAdmin({ query: DELETE_DOMAIN_QUERY, variables: { id: report01ResolutionId } });
  });

  it('should load containers for the stream without hydrating their members', async () => {
    const reportId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const full = await storeLoadByIdWithRefs(testContext, ADMIN_USER, reportId) as any;
    const base = await storeLoadByIdWithRefs(testContext, ADMIN_USER, reportId, { objectsBaseData: true }) as any;
    expect(full.objects.length).toBeGreaterThan(0);
    expect(base.objects.length).toBe(full.objects.length);
    // Members only keep their base data, authors and markings stay complete
    const fullDataIds = new Set([full.createdBy?.internal_id, ...(full.objectMarking ?? []).map((m: any) => m.internal_id)]);
    const onlyMembers = base.objects.filter((o: any) => !fullDataIds.has(o.internal_id));
    expect(onlyMembers.length).toBeGreaterThan(0);
    onlyMembers.forEach((member: any) => {
      expect(member.standard_id).toBeDefined();
      expect(member.created_at).toBeUndefined();
    });
    expect(base.objectMarking).toEqual(full.objectMarking);
    // STIX conversion is unchanged
    expect(convertStoreToStix_2_1(base as StoreObject)).toEqual(convertStoreToStix_2_1(full as StoreObject));
  });
});
