import submitOperation from '../../config';

const riskAnalysisQuery = `query RiskUI_analysis {
    risk(id: "d67ba9c2-9421-4e3e-ba6c-8a3ab382dc3a") {
      id
      characterizations {
        id
        entity_type
        created
        modified
        origins {
          # source of detection
          id
          origin_actors {
            actor_type
            actor_ref {
              ... on AssessmentPlatform {
                id
                name # Source
              }
              ... on Component {
                id
                component_type
                name
              }
              ... on OscalParty {
                id
                party_type
                name # Source
              }
            }
          }
        }
        facets {
          id
          entity_type
          risk_state
          source_system
          facet_name
          facet_value
        }
        links {
          id
          source_name
          external_id
          url
        }
        remarks {
          id
          created
          modified
          abstract
          content
          authors
        }
      }
      # threats {
      # }
    }
  }
  `;

describe('Risks Analysis Tests', () => {
  it('Return risk analysis details', async () => {
    const result = await submitOperation(riskAnalysisQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});
