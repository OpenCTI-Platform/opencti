import { describe, expect, it } from 'vitest';
import { createOperationDescriptor } from 'relay-runtime';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import PublicStixRelationshipsListQuery, { PublicStixRelationshipsListQuery$data } from './__generated__/PublicStixRelationshipsListQuery.graphql';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

const resolveRelationship = (to: Record<string, unknown>) => {
  const environment = createMockEnvironment();
  const operation = createOperationDescriptor(PublicStixRelationshipsListQuery, {
    uriKey: 'public-dashboard',
    widgetId: 'widget-id',
  });
  const payload = MockPayloadGenerator.generate(operation, {
    StixRelationshipConnection: () => ({
      edges: [{
        node: {
          __typename: 'StixCoreRelationship',
          relationship_type: 'cooperates-with',
          created: '2026-09-25T16:36:08.000Z',
          from: { __typename: 'ThreatActorIndividual', entity_type: 'Threat-Actor-Individual', name: 'BadBoy' },
          to,
        },
      }],
    }),
  });
  environment.commitPayload(operation, payload.data ?? {});
  const data = environment.lookup(operation.fragment).data as PublicStixRelationshipsListQuery$data;
  return data.publicStixRelationships?.edges?.[0]?.node as Record<string, unknown>;
};

describe('PublicStixRelationshipsListQuery', () => {
  // The relationship columns (toName, toType...) display "Restricted" when an end is missing.
  it('should give the widget both ends of each relationship', () => {
    const node = resolveRelationship({ __typename: 'ThreatActorIndividual', entity_type: 'Threat-Actor-Individual', name: 'GoodBoy' });
    expect(node.from).toMatchObject({ entity_type: 'Threat-Actor-Individual', name: 'BadBoy' });
    expect(node.to).toMatchObject({ entity_type: 'Threat-Actor-Individual', name: 'GoodBoy' });
    expect(node.created).toEqual('2026-09-25T16:36:08.000Z');
  });

  it('should give the widget the representative of a target without name', () => {
    const node = resolveRelationship({ __typename: 'Grouping', entity_type: 'Grouping', representative: { main: 'Q3 review' } });
    expect(getMainRepresentative(node.to)).toEqual('Q3 review');
  });
});
