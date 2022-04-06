import submitOperation from '../../config';

const riskItemTrackingQuery = `query RiskUI_risk_items_tracking {
    risk(id: "d67ba9c2-9421-4e3e-ba6c-8a3ab382dc3a") {
      risk_log(first: 5) {
        edges {
          node {
            id
            entity_type
            entry_type     # used to determine icon
            name           # title
            description    # description under title
            logged_by {
              __typename
              id
              entity_type
              party {
                __typename
                id
                entity_type
                name
              }
              role {
                id
                entity_type
                role_identifier
                name
              }
            }
            # needed for expanded view
            event_start    # start date
            event_end      # end date
            status_change  # status change
            related_responses {
              id
              entity_type
              name
            }
          }
        }
      }
    }
  }`;

describe('Risks Item Tracking Tests', () => {
  it('Return a list of risk items', async () => {
    const result = await submitOperation(riskItemTrackingQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});
