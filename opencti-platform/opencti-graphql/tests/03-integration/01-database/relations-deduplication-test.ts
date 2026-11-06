import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import conf from '../../../src/config/conf';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

const CREATE_QUERY = gql`
  mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) {
      id
      first_seen
      last_seen
    }
  }
`;

const DELETE_QUERY = gql`
  mutation StixSightingRelationshipDelete($id: ID!) {
    stixSightingRelationshipEdit(id: $id) {
      delete
    }
  }
`;

// Dates far in the future so that no other sighting of the same pair can match
const at = (time: string) => `2030-06-15T${time}:00.000Z`;

describe('Relations deduplication with an ISO 8601 duration in past_days / next_days', () => {
  const createdIds = new Set<string>();

  const createUnitSighting = async (time: string) => {
    const result = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          fromId: 'indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079',
          toId: 'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c',
          first_seen: at(time),
          last_seen: at(time),
          attribute_count: 1,
        },
      },
    });
    const sighting = result.data?.stixSightingRelationshipAdd;
    createdIds.add(sighting.id);
    // Dates are returned as Date objects when the query runs in process
    return {
      id: sighting.id,
      first_seen: new Date(sighting.first_seen).toISOString(),
      last_seen: new Date(sighting.last_seen).toISOString(),
    };
  };

  beforeAll(() => {
    const originalGet = conf.get.bind(conf);
    const deduplicationConfig = {
      past_days: 30,
      next_days: 30,
      created_by_based: false,
      types_overrides: { [STIX_SIGHTING_RELATIONSHIP]: { past_days: 'PT30M', next_days: 'PT30M' } },
    };
    vi.spyOn(conf, 'get').mockImplementation((key?: string) => (key === 'relations_deduplication' ? deduplicationConfig : originalGet(key)));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    for (const id of createdIds) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id } });
    }
  });

  it('should merge unit sightings within 30 minutes of the stored bounds', async () => {
    const first = await createUnitSighting('10:05');
    const second = await createUnitSighting('10:20');
    const third = await createUnitSighting('10:34');
    expect(second.id).toEqual(first.id);
    expect(third.id).toEqual(first.id);
    expect(third.first_seen).toEqual(at('10:05'));
    expect(third.last_seen).toEqual(at('10:34'));
  });

  it('should open a new sighting 30 minutes or more after the first event', async () => {
    // Exactly 30 minutes after 10:05: bounds are strict, so it must not merge
    const sighting = await createUnitSighting('10:35');
    expect(createdIds.size).toEqual(2);
    expect(sighting.first_seen).toEqual(at('10:35'));
  });

  it('should keep every sighting shorter than 30 minutes with out-of-order events', async () => {
    // 10:00 is within 30 minutes of 10:05 but not of 10:34 nor 10:35: it cannot join any stored sighting
    const sighting = await createUnitSighting('10:00');
    expect(createdIds.size).toEqual(3);
    expect(sighting.first_seen).toEqual(at('10:00'));
    expect(sighting.last_seen).toEqual(at('10:00'));
  });
});
