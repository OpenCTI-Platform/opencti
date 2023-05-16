import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

describe('StixRefRelationship', () => {
  let stixRefRelationshipInternalId;
  it('should StixRefRelationship created', async () => {
    const CREATE_QUERY = gql`
            mutation StixDomainRelationAdd($input: StixRefRelationshipAddInput!) {
                stixRefRelationshipAdd(input: $input) {
                    id
                    spec_version
                    from {
                        ... on Malware {
                            id
                            x_opencti_stix_ids
                        }
                    }
                }
            }
        `;
    // Create the stixRefRelationship
    const STIX_RELATION_TO_CREATE = {
      input: {
        fromId: 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
        toId: 'software--b0debdba-74e7-4463-ad2a-34334ee66d8d',
        relationship_type: 'operating-system',
      },
    };
    const stixRefRelationship = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_RELATION_TO_CREATE,
    });

    expect(stixRefRelationship.data.stixRefRelationshipAdd).not.toBeNull();
    expect(stixRefRelationship.data.stixRefRelationshipAdd.spec_version).toEqual('2.1');
    expect(stixRefRelationship.data.stixRefRelationshipAdd.from.x_opencti_stix_ids[0]).toEqual('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    stixRefRelationshipInternalId = stixRefRelationship.data.stixRefRelationshipAdd.id;
  });
  it('should stixRefRelationship deleted', async () => {
    const READ_QUERY = gql`
            query stixRefRelationship($id: String!) {
                stixRefRelationship(id: $id) {
                    id
                }
            }
        `;
    const DELETE_QUERY = gql`
          mutation stixRefRelationshipDelete($id: ID!) {
              stixRefRelationshipEdit(id: $id) {
                  delete
              }
          }
      `;
    // Delete the stixRefRelationship
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixRefRelationshipInternalId },
    });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRefRelationshipInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRefRelationship).toBeNull();
  });
});
