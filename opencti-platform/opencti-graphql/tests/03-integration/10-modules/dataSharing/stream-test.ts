import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { type StreamCollectionAddInput } from '../../../../src/generated/graphql';
import { getBaseUrl, logApp } from '../../../../src/config/conf';
import { getGroupEntity } from '../../../utils/domainQueryHelper';
import { ADMIN_USER, AMBER_GROUP, getUserIdByEmail, ONE_MINUTE, USER_CONNECTOR, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { MEMBER_ACCESS_RIGHT_VIEW } from '../../../../src/utils/access';
import { MARKING_TLP_AMBER, MARKING_TLP_RED } from '../../../../src/schema/identifier';
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

const CREATE_MALWARE_QUERY = gql`
  mutation streamRefsMalwareAdd($input: MalwareAddInput!) {
    malwareAdd(input: $input) {
      id
      standard_id
    }
  }
`;

const CREATE_REPORT_QUERY = gql`
  mutation streamRefsReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
      standard_id
    }
  }
`;

const EDIT_DOMAIN_QUERY = gql`
  mutation streamRefsDomainEdit($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const DELETE_DOMAIN_QUERY = gql`
  mutation streamRefsDomainDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) {
      delete
    }
  }
`;

const CREATE_STREAM_QUERY = gql`
  mutation streamRefsStreamAdd($input: StreamCollectionAddInput!) {
    streamCollectionAdd(input: $input) {
      id
    }
  }
`;

const DELETE_STREAM_QUERY = gql`
  mutation streamRefsStreamDelete($id: ID!) {
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

/**
 * Reads a live stream replayed from `from` until `isExpected` matches. Events are replayed from
 * Redis through the live publication path, which is the only place where object refs are redacted,
 * so the result cannot be observed through a GraphQL query nor through the `recover` mode.
 */
const readStreamUntil = async (
  streamUrl: string,
  isExpected: (message: SseMessage) => boolean,
  timeoutMs = 10000,
) => {
  const response = await fetch(streamUrl, { headers: { Accept: 'text/event-stream' }, signal: AbortSignal.timeout(timeoutMs) });
  expect(response.status).toBe(200);
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  const received: SseMessage[] = [];
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
        if (message) {
          received.push(message);
          if (isExpected(message)) {
            await reader.cancel();
            return received;
          }
        }
        separatorIndex = buffer.indexOf('\n\n');
      }
    }
  } catch (error: any) {
    logApp.info('Stream read ended:', { streamUrl, cause: error });
  }
  throw new Error(`Expected event never received on ${streamUrl}, got ${received.length} messages`);
};

describe('Stream object refs filtering', () => {
  let unmarkedMalwareId: string;
  let unmarkedMalwareStandardId: string;
  let amberMalwareId: string;
  let amberMalwareStandardId: string;
  let redMalwareId: string;
  let redMalwareStandardId: string;
  let reportId: string;
  let amberStreamId: string;
  let unrestrictedStreamId: string;

  // A report standard id is derived from its name, so the stable internal id identifies the event
  const isReportUpdate = (message: SseMessage) => message.event === 'update'
    && message.data.data.extensions?.[STIX_EXT_OCTI]?.id === reportId;

  const createMalware = async (name: string, objectMarking: string[] = []) => {
    const malware = await queryAsAdminWithSuccess({
      query: CREATE_MALWARE_QUERY,
      variables: { input: { name, objectMarking } },
    });
    return malware.data.malwareAdd;
  };

  const createReportStream = async (name: string, publicUserId: string) => {
    const streamInput: StreamCollectionAddInput = {
      name,
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Report'], mode: 'or' }], filterGroups: [] }),
      stream_live: true,
      stream_public: true,
      stream_public_user_id: publicUserId,
    };
    const stream = await queryAsAdminWithSuccess({ query: CREATE_STREAM_QUERY, variables: { input: streamInput } });
    return stream.data.streamCollectionAdd.id;
  };

  // The stream processor of a fresh connection starts at the end of the Redis stream, so the update
  // must be published first and replayed with a `from` older than it.
  const updateReport = async (key: string, value: string) => {
    const fromEventId = `${Date.now() - 1000}-0`;
    await queryAsAdminWithSuccess({
      query: EDIT_DOMAIN_QUERY,
      variables: { id: reportId, input: [{ key, value: [value] }] },
    });
    return fromEventId;
  };

  beforeAll(async () => {
    const unmarkedMalware = await createMalware('Stream-Refs-Unmarked-Malware');
    unmarkedMalwareId = unmarkedMalware.id;
    unmarkedMalwareStandardId = unmarkedMalware.standard_id;

    const amberMalware = await createMalware('Stream-Refs-Amber-Malware', [MARKING_TLP_AMBER]);
    amberMalwareId = amberMalware.id;
    amberMalwareStandardId = amberMalware.standard_id;

    const redMalware = await createMalware('Stream-Refs-Red-Malware', [MARKING_TLP_RED]);
    redMalwareId = redMalware.id;
    redMalwareStandardId = redMalware.standard_id;

    const report = await queryAsAdminWithSuccess({
      query: CREATE_REPORT_QUERY,
      variables: {
        input: {
          name: 'Stream-Refs-Report',
          published: '2023-10-06T00:00:00.000Z',
          objectMarking: [MARKING_TLP_AMBER],
          objects: [unmarkedMalwareId, amberMalwareId, redMalwareId],
        },
      },
    });
    reportId = report.data.reportAdd.id;

    // USER_EDITOR belongs to AMBER GROUP, a stream published with his rights must not expose TLP:RED
    const editorUserId = await getUserIdByEmail(USER_EDITOR.email);
    amberStreamId = await createReportStream('Public stream restricted to a TLP:AMBER user', editorUserId);
    unrestrictedStreamId = await createReportStream('Public stream with an unrestricted user', ADMIN_USER.id);
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: DELETE_STREAM_QUERY, variables: { id: unrestrictedStreamId } });
    await queryAsAdminWithSuccess({ query: DELETE_STREAM_QUERY, variables: { id: amberStreamId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_QUERY, variables: { id: reportId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_QUERY, variables: { id: redMalwareId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_QUERY, variables: { id: amberMalwareId } });
    await queryAsAdminWithSuccess({ query: DELETE_DOMAIN_QUERY, variables: { id: unmarkedMalwareId } });
  });

  it('Should not send the object refs restricted for the stream public user', async () => {
    const fromEventId = await updateReport('name', 'Stream-Refs-Report-Renamed');
    const messages = await readStreamUntil(`${getBaseUrl()}/stream/${amberStreamId}?from=${fromEventId}`, isReportUpdate);

    // TLP:RED is above the allowed markings of the stream public user
    const { object_refs: objectRefs } = messages[messages.length - 1].data.data;
    expect(objectRefs).toHaveLength(2);
    expect(objectRefs).toContain(unmarkedMalwareStandardId);
    expect(objectRefs).toContain(amberMalwareStandardId);
    expect(objectRefs).not.toContain(redMalwareStandardId);

    // The restricted malware is not published as a dependency either, no dangling ref is sent
    const publishedIds = messages.filter((message) => message.event === 'create').map((message) => message.data.data.id);
    expect(publishedIds).toContain(unmarkedMalwareStandardId);
    expect(publishedIds).toContain(amberMalwareStandardId);
    expect(publishedIds).not.toContain(redMalwareStandardId);
  }, ONE_MINUTE);

  it('Should send all the object refs when the stream public user has no restriction', async () => {
    const fromEventId = await updateReport('description', 'Stream-Refs-Report description');
    const messages = await readStreamUntil(`${getBaseUrl()}/stream/${unrestrictedStreamId}?from=${fromEventId}`, isReportUpdate);

    const { object_refs: objectRefs } = messages[messages.length - 1].data.data;
    expect(objectRefs).toHaveLength(3);
    expect(objectRefs).toContain(unmarkedMalwareStandardId);
    expect(objectRefs).toContain(amberMalwareStandardId);
    expect(objectRefs).toContain(redMalwareStandardId);
  }, ONE_MINUTE);
});
