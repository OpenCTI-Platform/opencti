import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useBuildAttributesOutcome from './useBuildAttributesOutcome';
import * as filterUtils from '../../../filters/filtersUtils';
import * as objectUtils from '../../../object';
import { SELF_ID } from '../../../filters/filtersUtils';

describe('Hook: useBuildAttributesOutcome', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => new Map([
      ['created', { type: 'date' }],
    ]) as ReturnType<typeof filterUtils.useBuildFilterKeysMapFromEntityType>);
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should throw an error if no instance ID is given', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildAttributesOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op);
    });

    const call = () => buildAttributesOutcome('id_XX', { columns: [] });
    await expect(call).rejects.toThrowError('The attribute widget should refers to an instance');
  });

  it('should return resolved variables of the widget', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildAttributesOutcome } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        String(ctx) {
          if (ctx.name === 'name') return 'Super Report';
          return 'testing-data';
        },
        Label() {
          return { value: 'a-label' };
        },
        MarkingDefinition() {
          return { definition: 'tlp:red' };
        },
      });
    });

    const attributesOutcome = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'reportName', attribute: 'name', label: 'Name' },
          { variableName: 'reportLabels', attribute: 'objectLabel.value' },
          { variableName: 'reportMarkings', attribute: 'objectMarking.definition', displayStyle: 'list' },
        ],
      },
    );

    const name = attributesOutcome.find((o) => o.variableName === 'reportName')?.attributeData;
    const labels = attributesOutcome.find((o) => o.variableName === 'reportLabels')?.attributeData;
    const markings = attributesOutcome.find((o) => o.variableName === 'reportMarkings')?.attributeData;
    expect(name).toEqual('Super Report');
    expect(labels).toEqual('a-label');
    expect(markings).toEqual('<ul><li>tlp:red</li></ul>');
  });

  it('should preserve invalid property lookups per column when metadata is requested', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const propertySpy = vi.spyOn(objectUtils, 'getObjectPropertyWithoutEmptyValues').mockImplementation(() => {
      throw new Error('Invalid path "createdBy.name", a subpart is not an object');
    });
    const { buildAttributesOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => MockPayloadGenerator.generate(op));

    const outcomes = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [{ variableName: 'createdByName', attribute: 'createdBy.name' }],
      },
      { includeMetadata: true },
    );

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]).toMatchObject({
      variableName: 'createdByName',
      attributeData: '$createdByName',
      isEmpty: false,
      preserveSection: true,
    });
    expect(outcomes[0]?.error).toBeInstanceOf(Error);
    expect(String(outcomes[0]?.error)).toContain('Invalid path "createdBy.name", a subpart is not an object');
    propertySpy.mockRestore();
  });

  it('should preserve valid metadata columns when another metadata lookup is invalid', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockReturnValue({
      toPromise: async () => ({
        stixCoreObject: {
          name: 'Super Report',
          createdBy: null,
        },
      }),
    } as never);
    const { buildAttributesOutcome } = hook.result.current;

    const outcomes = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'reportName', attribute: 'name', label: 'Name' },
          { variableName: 'createdByName', attribute: 'createdBy.name', label: 'Author' },
        ],
      },
      { includeMetadata: true },
    );

    expect(outcomes).toHaveLength(2);
    expect(outcomes[0]).toEqual({
      variableName: 'reportName',
      attributeData: 'Super Report',
      isEmpty: false,
    });
    expect(outcomes[1]).toMatchObject({
      variableName: 'createdByName',
      attributeData: '$createdByName',
      isEmpty: false,
      preserveSection: true,
    });
    expect(outcomes[1]?.error).toBeInstanceOf(Error);
  });

  it('should classify raw empty values before formatting in metadata mode while preserving 0 and false', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockReturnValue({
      toPromise: async () => ({
        stixCoreObject: {
          x_opencti_score: 0,
          revoked: false,
          description: '',
          x_opencti_stix_ids: [],
          created: null,
          objectLabel: [{ value: '' }, { value: null }],
        },
      }),
    } as never);
    const { buildAttributesOutcome } = hook.result.current;

    const outcomes = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'score', attribute: 'x_opencti_score', label: 'Score' },
          { variableName: 'revoked', attribute: 'revoked', label: 'Revoked' },
          { variableName: 'description', attribute: 'description', label: 'Description' },
          { variableName: 'stixIds', attribute: 'x_opencti_stix_ids', label: 'STIX IDs', displayStyle: 'list' },
          { variableName: 'created', attribute: 'created', label: 'Created' },
          { variableName: 'labels', attribute: 'objectLabel.value', label: 'Labels', displayStyle: 'list' },
        ],
      },
      { includeMetadata: true },
    );

    expect(outcomes).toEqual([
      {
        variableName: 'score',
        attributeData: '0',
        isEmpty: false,
      },
      {
        variableName: 'revoked',
        attributeData: 'false',
        isEmpty: false,
      },
      {
        variableName: 'description',
        attributeData: '',
        isEmpty: true,
      },
      {
        variableName: 'stixIds',
        attributeData: '',
        isEmpty: true,
      },
      {
        variableName: 'created',
        attributeData: '',
        isEmpty: true,
      },
      {
        variableName: 'labels',
        attributeData: '',
        isEmpty: true,
      },
    ]);
  });

  it('should keep legacy attribute replacement behavior when metadata is not requested', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const propertySpy = vi.spyOn(objectUtils, 'getObjectPropertyWithoutEmptyValues').mockImplementation(() => {
      throw new Error('Invalid path "createdBy.name", a subpart is not an object');
    });
    const { buildAttributesOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => MockPayloadGenerator.generate(op));

    const outcomes = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [{ variableName: 'createdByName', attribute: 'createdBy.name' }],
      },
    );

    expect(outcomes).toEqual([
      {
        variableName: 'createdByName',
        attributeData: '',
        isEmpty: false,
      },
    ]);
    propertySpy.mockRestore();
  });
});
