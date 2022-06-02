import submitOperation from '../../config';

const riskObservationDetailsQuery = `query RiskUI_observation_details {
    observation(id: "83909f2d-2852-4944-b520-e48e30ed4d20") {
      __typename
      id
      entity_type
      name
      description
      methods
      observation_types
      collected
      origins {
        origin_actors {
          # actor_type
          actor_ref {
            ... on AssessmentPlatform {
              id
              name
            }
            ... on Component {
              id
              component_type
              name
            }
            ... on OscalParty {
              id
              party_type
              name
            }
          }
        }
      }
      subjects {
        id
        entity_type
        name
        subject_context
        subject_type
        subject_ref {
          ... on Component {
            id
            entity_type
            name
          }
          ... on InventoryItem {
            id
            entity_type
            name
          }
          ... on OscalLocation {
            id
            entity_type
            name
          }
          ... on OscalParty {
            id
            entity_type
            name
          }
          ... on OscalUser {
            id
            entity_type
            name
          }
        }
      }
    }
  }
  `;

describe('Risks Observation Details Tests', () => {
  it('Return risk observation details', async () => {
    const result = await submitOperation(riskObservationDetailsQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});
