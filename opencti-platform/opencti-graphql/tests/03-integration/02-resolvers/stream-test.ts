import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { type StreamCollectionAddInput } from '../../../src/generated/graphql';
import { logApp } from '../../../src/config/conf';
import { getGroupEntity } from '../../utils/domainQueryHelper';
import { AMBER_GROUP, USER_CONNECTOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { MEMBER_ACCESS_RIGHT_VIEW } from '../../../src/utils/access';

describe('Stream resolver coverage', () => {
  let publicStreamId: string;
  let amberRestrictedStreamId: string;
  let restrictedStreamId: string;

  it('Create new public stream collection', async () => {
    const publicStreamInput: StreamCollectionAddInput = {
      description: 'Public stream for resolver tests - description',
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Domain-Name'], mode: 'or' }], filterGroups: [] }),
      name: 'Public stream for resolver tests',
      stream_public: true
    };

    const publicStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
        mutation streamCollectionAdd($input: StreamCollectionAddInput!) {
            streamCollectionAdd(input: $input) {
                id
                name
                stream_public
                filters
                description
                authorized_members {
                    id
                    name
                }
            }
        },
    `,
      variables: { input: publicStreamInput }
    });

    logApp.info('publicStreamResponse:', publicStreamResponse);
    expect(publicStreamResponse?.data?.streamCollectionAdd?.id).toBeDefined();
    publicStreamId = publicStreamResponse?.data?.streamCollectionAdd?.id;

    expect(publicStreamResponse?.data?.streamCollectionAdd?.name).toBe('Public stream for resolver tests');
    expect(publicStreamResponse?.data?.streamCollectionAdd?.description).toBe('Public stream for resolver tests - description');
    expect(publicStreamResponse?.data?.streamCollectionAdd?.stream_public).toBeTruthy();
    expect(publicStreamResponse?.data?.streamCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Domain-Name'], mode: 'or' }], filterGroups: [] }));
  });

  it('Create restricted to group stream collection', async () => {
    const amberGroup = await getGroupEntity(AMBER_GROUP);

    const amberRestrictedStreamInput: StreamCollectionAddInput = {
      description: 'Restricted to AMBER stream for resolver tests - description',
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['City'], mode: 'or' }], filterGroups: [] }),
      name: 'Restricted to AMBER stream for resolver tests',
      stream_public: false,
      authorized_members: [{ id: amberGroup.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }]
    };

    const amberRestrictedStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation streamCollectionAdd($input: StreamCollectionAddInput!) {
                    streamCollectionAdd(input: $input) {
                        id
                        name
                        stream_public
                        filters
                        description
                        authorized_members {
                            id
                            name
                        }
                    }
                },
            `,
      variables: { input: amberRestrictedStreamInput }
    });

    logApp.info('amberRestrictedStreamResponse:', amberRestrictedStreamResponse);
    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.id).toBeDefined();
    amberRestrictedStreamId = amberRestrictedStreamResponse?.data?.streamCollectionAdd?.id;

    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.name).toBe('Restricted to AMBER stream for resolver tests');
    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.description).toBe('Restricted to AMBER stream for resolver tests - description');
    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.stream_public).toBeFalsy();
    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.authorized_members.length).toBe(1);
    expect(amberRestrictedStreamResponse?.data?.streamCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['City'], mode: 'or' }], filterGroups: [] }));
  });

  it('Create no public but no restricted yet stream collection', async () => {
    const restrictedStreamInput: StreamCollectionAddInput = {
      description: 'Not public stream with empty auth member for resolver tests - description',
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['confidence'], operator: 'gt', values: [50], mode: 'or' }], filterGroups: [] }),
      name: 'Not public stream with empty auth member for resolver tests',
      stream_public: false,
    };

    const restrictedStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation streamCollectionAdd($input: StreamCollectionAddInput!) {
                    streamCollectionAdd(input: $input) {
                        id
                        name
                        stream_public
                        filters
                        description
                        authorized_members {
                            id
                            name
                        }
                    }
                },
            `,
      variables: { input: restrictedStreamInput }
    });

    logApp.info('amberRestrictedStreamResponse:', restrictedStreamResponse);
    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.id).toBeDefined();
    restrictedStreamId = restrictedStreamResponse?.data?.streamCollectionAdd?.id;

    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.name).toBe('Not public stream with empty auth member for resolver tests');
    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.description).toBe('Not public stream with empty auth member for resolver tests - description');
    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.stream_public).toBeFalsy();
    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.authorized_members.length).toBe(0);
    expect(restrictedStreamResponse?.data?.streamCollectionAdd?.filters).toBe(JSON.stringify({ mode: 'and', filters: [{ key: ['confidence'], operator: 'gt', values: [50], mode: 'or' }], filterGroups: [] }));
  });

  it('List all stream with Admin', async () => {
    const allStreamsResponse = await queryAsAdminWithSuccess({
      query: gql`
                query streamCollections {
                    streamCollections(search: "") {
                        edges {
                            node {
                                id
                                name
                                authorized_members {
                                    id
                                    name
                                }
                            }
                        }
                    }
                },
            `,
      variables: {}
    });

    logApp.info('allStreamsResponse:', allStreamsResponse);
    // Restricted stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Restricted to AMBER stream for resolver tests').length).toBe(1);

    // Internal stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Not public stream with empty auth member for resolver tests').length).toBe(1);

    // Public stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Public stream for resolver tests').length).toBe(1);
  });

  it('List all stream with a user that has TAXIIAPI capacity', async () => {
    const allStreamsResponse = await queryAsUserWithSuccess(USER_CONNECTOR.client, {
      query: gql`
              query streamCollections {
                  streamCollections(search: "") {
                      edges {
                          node {
                              id
                              name
                              authorized_members {
                                  id
                                  name
                              }
                          }
                      }
                  }
              },
          `,
      variables: {}
    });

    logApp.info('allStreamsResponse:', allStreamsResponse);
    // Restricted stream should not be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Restricted to AMBER stream for resolver tests').length).toBe(0);

    // Internal stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Not public stream with empty auth member for resolver tests').length).toBe(1);

    // Public stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Public stream for resolver tests').length).toBe(1);
  });

  it('List all stream with a user that has not TAXIIAPI capacity', async () => {
    const allStreamsResponse = await queryAsUser(USER_PARTICIPATE.client, {
      query: gql`
                query streamCollections {
                    streamCollections(search: "") {
                        edges {
                            node {
                                id
                                name
                                authorized_members {
                                    id
                                    name
                                }
                            }
                        }
                    }
                },
            `,
      variables: {}
    });

    logApp.info('allStreamsResponse:', allStreamsResponse);
    // Restricted stream should not be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Restricted to AMBER stream for resolver tests').length).toBe(0);

    // Internal stream should not be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Not public stream with empty auth member for resolver tests').length).toBe(0);

    // Public stream should be found
    expect(allStreamsResponse?.data?.streamCollections?.edges
      .filter((stream: any) => stream.node.name === 'Public stream for resolver tests').length).toBe(1);
  });

  it('Delete public stream collection', async () => {
    const deletePublicStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
              mutation streamCollectionEdit($id: ID!) {
                  streamCollectionEdit(id: $id) {
                      delete
                  }
              },
          `,
      variables: { id: publicStreamId }
    });
    logApp.info('deletePublicStreamResponse:', deletePublicStreamResponse);
    expect(deletePublicStreamResponse?.data?.streamCollectionEdit?.delete).toBeDefined();
  });

  it('Delete restricted to group stream collection', async () => {
    const deleteGroupRestrictedStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation streamCollectionEdit($id: ID!) {
                    streamCollectionEdit(id: $id) {
                        delete
                    }
                },
            `,
      variables: { id: amberRestrictedStreamId }
    });
    logApp.info('deleteGroupRestrictedStreamResponse:', deleteGroupRestrictedStreamResponse);
    expect(deleteGroupRestrictedStreamResponse?.data?.streamCollectionEdit?.delete).toBeDefined();
  });

  it('Delete not public stream collection', async () => {
    const deleteRestrictedStreamResponse = await queryAsAdminWithSuccess({
      query: gql`
                mutation streamCollectionEdit($id: ID!) {
                    streamCollectionEdit(id: $id) {
                        delete
                    }
                },
            `,
      variables: { id: restrictedStreamId }
    });
    logApp.info('deleteRestrictedStreamResponse:', deleteRestrictedStreamResponse);
    expect(deleteRestrictedStreamResponse?.data?.streamCollectionEdit?.delete).toBeDefined();
  });
});
