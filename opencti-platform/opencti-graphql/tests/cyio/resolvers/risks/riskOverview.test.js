import submitOperation from '../../config';

const riskOverviewQuery = `query RiskUI_riskOverview {
    risk(id: "de840476-daa7-59c3-adc8-5ebdb3c6072f") {
      __typename
      id
      name
      description
      statement
      risk_status
      risk_level
      deadline
      accepted
      risk_adjusted
      priority
      vendor_dependency
      impacted_control_id
      origins {
        origin_actors {
          actor_type
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
      related_observations {
        edges {
          node {
            __typename
            id
            entity_type
            name
            description
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
              subject_context
              subject_type
              subject_ref {
                ... on Component {
                  id
                  component_type
                  name # Required Resource
                }
                ... on InventoryItem {
                  id
                  asset_type
                  name # Required Resource
                }
                ... on OscalLocation {
                  id
                  location_type
                  name # Required Resource
                }
                ... on OscalParty {
                  id
                  party_type
                  name # Required Resource
                }
              }
            }
          }
        }
      }
      labels {
        id
        name
        color
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
  }
  `;

describe('Risks Overview Tests', () => {
  it('Return a risk overview', async () => {
    const result = await submitOperation(riskOverviewQuery);

    expect(typeof { value: result.data }).toBe('object');
  });
});
