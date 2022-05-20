import submitOperation from '../../config';

const risksQuery = `query RiskUI_risks {
    poamItems(first: 100) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          __typename
          id
          poam_id
          name
          occurrences
          related_risks {
            edges {
              node {
                __typename
                id
                name
                risk_status
                risk_level
                deadline
                remediations {
                  __typename
                  id
                  response_type
                  lifecycle
                }
              }
            }
          }
        }
      }
    }
  }`;

describe('Risks Tests', () => {
  it('Return a list of poam items', async () => {
    const result = await submitOperation(risksQuery);
    expect(typeof { value: result.data }).toBe('object');
  });
});
