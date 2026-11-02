import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { type StreamCollectionAddInput } from '../../../../src/generated/graphql';
import { getBaseUrl, logApp } from '../../../../src/config/conf';
import { getGroupEntity } from '../../../utils/domainQueryHelper';
import { ADMIN_USER, AMBER_GROUP, generateBasicAuth, ONE_MINUTE, testContext, USER_CONNECTOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { MEMBER_ACCESS_RIGHT_VIEW } from '../../../../src/utils/access';
import { stixDomainObjectEditField } from '../../../../src/domain/stixDomainObject';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

describe('Stream resolver coverage', () => {
  let publicStreamId: string;
  let amberRestrictedStreamId: string;
  let restrictedStreamId: string;

  it('Create new public stream collection', async () => {
    const publicStreamInput: StreamCollectionAddInput = {
      description: 'Public stream for resolver tests - description',
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Domain-Name'], mode: 'or' }], filterGroups: [] }),
      name: 'Public stream for resolver tests',
      stream_public: true,
      stream_public_user_id: ADMIN_USER.id,
      stream_live: true,
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
      variables: { input: publicStreamInput },
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
      authorized_members: [{ id: amberGroup.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }],
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
      variables: { input: amberRestrictedStreamInput },
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
      variables: { input: restrictedStreamInput },
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
      variables: {},
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
    const allStreamsResponse = await queryAsUserWithSuccess(USER_CONNECTOR, {
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
      variables: {},
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
    const allStreamsResponse = await queryAsUser(USER_PARTICIPATE, {
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
      variables: {},
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

  it('should access public SSE stream without authentication (covers authenticateForPublic)', async () => {
    const response = await fetch(`${getBaseUrl()}/stream/${publicStreamId}`, {
      headers: { Accept: 'text/event-stream' },
    });
    await response.body?.cancel();
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/event-stream');
  });

  it('should reject unauthenticated access to restricted SSE stream', async () => {
    const response = await fetch(`${getBaseUrl()}/stream/${restrictedStreamId}`, {
      headers: { Accept: 'text/event-stream' },
    });
    expect(response.status).toBe(410);
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
      variables: { id: publicStreamId },
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
      variables: { id: amberRestrictedStreamId },
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
      variables: { id: restrictedStreamId },
    });
    logApp.info('deleteRestrictedStreamResponse:', deleteRestrictedStreamResponse);
    expect(deleteRestrictedStreamResponse?.data?.streamCollectionEdit?.delete).toBeDefined();
  });
});

const STREAM_ORIGIN_REPORT_ADD_QUERY = gql`
  mutation streamOriginReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;

const STREAM_ORIGIN_REPORT_DELETE_QUERY = gql`
  mutation streamOriginReportDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) {
      delete
    }
  }
`;

const STREAM_ORIGIN_STREAM_ADD_QUERY = gql`
  mutation streamOriginStreamAdd($input: StreamCollectionAddInput!) {
    streamCollectionAdd(input: $input) {
      id
    }
  }
`;

const STREAM_ORIGIN_STREAM_DELETE_QUERY = gql`
  mutation streamOriginStreamDelete($id: ID!) {
    streamCollectionEdit(id: $id) {
      delete
    }
  }
`;

interface SseMessage { event: string; data: any }

const parseSseMessage = (rawMessage: string): SseMessage | undefined => {
  const lines = rawMessage.split('\n');
  const event = lines.find((line) => line.startsWith('event: '))?.substring(7);
  const data = lines.find((line) => line.startsWith('data: '))?.substring(6);
  return event && data ? { event, data: JSON.parse(data) } : undefined;
};

// Reads a live stream replayed from `from` until `isExpected` matches
const readStreamUntil = async (streamUrl: string, isExpected: (message: SseMessage) => boolean, timeoutMs = 30000) => {
  const headers = { Accept: 'text/event-stream', authorization: generateBasicAuth() };
  const response = await fetch(streamUrl, { headers, signal: AbortSignal.timeout(timeoutMs) });
  expect(response.status).toBe(200);
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    let isReading = true;
    while (isReading) {
      const { value, done } = await reader.read();
      isReading = !done;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      let separatorIndex = buffer.indexOf('\n\n');
      while (separatorIndex >= 0) {
        const message = parseSseMessage(buffer.substring(0, separatorIndex));
        buffer = buffer.substring(separatorIndex + 2);
        if (message && isExpected(message)) {
          await reader.cancel();
          return message;
        }
        separatorIndex = buffer.indexOf('\n\n');
      }
    }
  } catch (error: any) {
    logApp.info('Stream read ended:', { streamUrl, cause: error });
  }
  throw new Error(`Expected event never received on ${streamUrl}`);
};

describe('Stream event origin', () => {
  let reportId: string;
  let streamId: string;

  beforeAll(async () => {
    const report = await queryAsAdminWithSuccess({
      query: STREAM_ORIGIN_REPORT_ADD_QUERY,
      variables: { input: { name: 'Stream-Origin-Report', published: '2023-10-06T00:00:00.000Z' } },
    });
    reportId = report.data.reportAdd.id;
    const streamInput: StreamCollectionAddInput = {
      name: 'Stream origin',
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Report'], mode: 'or' }], filterGroups: [] }),
      stream_live: true,
      stream_public: false,
    };
    const stream = await queryAsAdminWithSuccess({ query: STREAM_ORIGIN_STREAM_ADD_QUERY, variables: { input: streamInput } });
    streamId = stream.data.streamCollectionAdd.id;
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: STREAM_ORIGIN_STREAM_DELETE_QUERY, variables: { id: streamId } });
    await queryAsAdminWithSuccess({ query: STREAM_ORIGIN_REPORT_DELETE_QUERY, variables: { id: reportId } });
  });

  it('Should only publish the stream origin attributes', async () => {
    // The stream processor of a fresh connection starts at the end of the redis stream, replay from before the update
    const fromEventId = `${Date.now() - 1000}-0`;
    const description = 'Stream-Origin-Report description';
    const userWithOrigin = {
      ...ADMIN_USER,
      origin: { socket: 'query', ip: 'value', user_id: ADMIN_USER.id, user_metadata: { key: 'value' }, referer: 'value' },
    };
    await stixDomainObjectEditField(testContext, userWithOrigin, reportId, [{ key: 'description', value: [description] }]);
    const isOriginUpdate = (message: SseMessage) => message.event === 'update'
      && message.data.data.extensions?.[STIX_EXT_OCTI]?.id === reportId
      && message.data.data.description === description;
    const message = await readStreamUntil(`${getBaseUrl()}/stream/${streamId}?from=${fromEventId}`, isOriginUpdate);

    expect(message.data.origin).toEqual({ socket: 'query', user_id: ADMIN_USER.id });
  }, ONE_MINUTE);
});
