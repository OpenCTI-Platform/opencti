import submitOperation from '../../config';

const riskRemediationDetailsQuery = `query RiskUI_remediation_details {
    riskResponse(id: "79191464-5c3c-54ac-a17d-cb322f8babd6") {
      id
      entity_type
      name # Title
      description # Description
      created # Created
      modified # Last Modified
      response_type # Response Type
      lifecycle # Lifecycle
      origins {
        # Detection Source
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
      required_assets { # Required Resources
        id
        subjects {
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
              name  # Required Resource
            }
            ... on OscalParty {
              id
              party_type
              name # Required Resource
            }
          }
        }
      }
      tasks {   # Related Tasks
        id
        task_type
        name
        description
      }
      links {
        id
        created
        modified
        description # description
        url # URL
      }
      remarks {
        id
        created
        abstract
      }
    }
  }
  `;

describe('Risks Remediation Details Tests', () => {
  it('Return risk remediation details', async () => {
    const result = await submitOperation(riskRemediationDetailsQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});
