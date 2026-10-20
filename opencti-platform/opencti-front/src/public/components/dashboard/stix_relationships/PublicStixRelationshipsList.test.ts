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
  // The relationship columns (to_entity_type, to_relationship_type) display "Restricted" when an end is missing.
  it('should give the widget both ends of each relationship', () => {
    const node = resolveRelationship({
      __typename: 'ThreatActorIndividual',
      entity_type: 'Threat-Actor-Individual',
      representative: { main: 'GoodBoy' },
    });
    expect(node.from).toMatchObject({ entity_type: 'Threat-Actor-Individual', name: 'BadBoy' });
    expect(node.to).toMatchObject({ entity_type: 'Threat-Actor-Individual' });
    expect(getMainRepresentative(node.to)).toEqual('GoodBoy');
    expect(node.created).toEqual('2026-09-25T16:36:08.000Z');
  });

  it.each([
    { kind: 'entity without name', to: { __typename: 'Grouping', entity_type: 'Grouping', representative: { main: 'Q3 review' } } },
    { kind: 'shared organization', to: { __typename: 'Organization', entity_type: 'Organization', representative: { main: 'JamieC Incorporated' } } },
    { kind: 'marking definition', to: { __typename: 'MarkingDefinition', entity_type: 'Marking-Definition', representative: { main: 'TLP:AMBER' } } },
    { kind: 'relationship', to: { __typename: 'StixCoreRelationship', entity_type: 'uses', representative: { main: 'APT1 uses Mimikatz' } } },
  ])('should give the widget the type and representative of a $kind target', ({ to }) => {
    const node = resolveRelationship(to);
    expect(node.to).toMatchObject({ entity_type: to.entity_type });
    expect(getMainRepresentative(node.to)).toEqual(to.representative.main);
  });
});
