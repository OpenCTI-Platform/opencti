import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useBuildAttributesOutcome, { isReadThroughNotAllowedObject, selectsLatestInvestigationRun } from './useBuildAttributesOutcome';
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

  it('should treat a null intermediate value as an empty value in metadata mode', async () => {
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

    expect(outcomes).toEqual([
      { variableName: 'reportName', attributeData: 'Super Report', isEmpty: false },
      { variableName: 'createdByName', attributeData: '', isEmpty: true },
    ]);
  });

  it('should preserve valid metadata columns when another metadata lookup goes through a non-object value', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockReturnValue({
      toPromise: async () => ({
        stixCoreObject: {
          name: 'Super Report',
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
          { variableName: 'nameValue', attribute: 'name.value', label: 'Invalid' },
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
      variableName: 'nameValue',
      attributeData: '$nameValue',
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

  it('should return the value of a custom field', async () => {
    const { hook, relayEnv } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildAttributesOutcome } = hook.result.current;

    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        CustomFieldValue() {
          return {
            field_id: 'cf-1',
            field_name: 'x_opencti_cf_note',
            string_value: 'cloture',
            int_value: null,
            boolean_value: null,
            date_value: null,
            select_value: null,
            select_values: null,
          };
        },
      });
    });

    const attributesOutcome = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'analystNote', attribute: 'x_opencti_cf_note', label: 'Analyst note' },
        ],
      },
    );

    expect(attributesOutcome).toEqual([{ variableName: 'analystNote', attributeData: 'cloture', isEmpty: false }]);
  });

  it('should treat a missing custom field as an empty value in metadata mode, but not a false one', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    vi.spyOn(env, 'fetchQuery').mockReturnValue({
      toPromise: async () => ({
        stixCoreObject: {
          customFieldValues: [{ field_id: 'cf-1', field_name: 'x_opencti_cf_flag', boolean_value: false }],
        },
      }),
    } as never);
    const { buildAttributesOutcome } = hook.result.current;

    const outcomes = await buildAttributesOutcome(
      'id_XX',
      {
        instance_id: SELF_ID,
        columns: [
          { variableName: 'flag', attribute: 'x_opencti_cf_flag', label: 'Flag' },
          { variableName: 'note', attribute: 'x_opencti_cf_note', label: 'Note' },
        ],
      },
      { includeMetadata: true },
    );

    expect(outcomes).toMatchObject([
      { variableName: 'flag', isEmpty: false },
      { variableName: 'note', attributeData: '', isEmpty: true },
    ]);
  });

  it('should withhold the values read through a nested object marked above the limits of the export', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    const stixCoreObject = {
      name: 'Phishing case',
      latestInvestigationRun: {
        objectMarking: [{ id: 'tlp-red' }],
        report_sections: { executive_summary: 'Attributed to the intrusion set' },
      },
    };
    vi.spyOn(env, 'fetchQuery').mockImplementation(() => ({ toPromise: async () => ({ stixCoreObject }) }) as unknown as ReturnType<typeof env.fetchQuery>);
    const { buildAttributesOutcome } = hook.result.current;

    const columns = [
      { variableName: 'caseName', attribute: 'name' },
      { variableName: 'summary', attribute: 'latestInvestigationRun.report_sections.executive_summary' },
      { variableName: 'run', attribute: 'latestInvestigationRun' },
    ];
    const withheld = await buildAttributesOutcome('id_XX', { instance_id: SELF_ID, columns }, undefined, ['tlp-red']);
    expect(withheld.find((o) => o.variableName === 'caseName')?.attributeData).toEqual('Phishing case');
    expect(withheld.find((o) => o.variableName === 'summary')?.attributeData).toEqual('Withheld: marked above the marking limits of this export');
    expect(withheld.find((o) => o.variableName === 'run')?.attributeData).toEqual('Withheld: marked above the marking limits of this export');
  });

  it('should only request the latest investigation run when a column reads it', async () => {
    const { hook } = testRenderHook(() => useBuildAttributesOutcome());
    const requestedVariables: unknown[] = [];
    vi.spyOn(env, 'fetchQuery').mockImplementation((_q, variables) => {
      requestedVariables.push(variables);
      return { toPromise: async () => ({ stixCoreObject: { name: 'Phishing case' } }) } as unknown as ReturnType<typeof env.fetchQuery>;
    });
    const { buildAttributesOutcome } = hook.result.current;

    await buildAttributesOutcome('id_XX', { instance_id: SELF_ID, columns: [{ variableName: 'caseName', attribute: 'name' }] });
    await buildAttributesOutcome('id_XX', {
      instance_id: SELF_ID,
      columns: [{ variableName: 'summary', attribute: 'latestInvestigationRun.report_sections.executive_summary' }],
    });
    expect(requestedVariables).toEqual([
      { id: 'id_XX', withInvestigationRun: false },
      { id: 'id_XX', withInvestigationRun: true },
    ]);
  });
});

describe('Function: selectsLatestInvestigationRun', () => {
  it('should select the run for a column reading the run or one of its fields', () => {
    expect(selectsLatestInvestigationRun([{ attribute: 'latestInvestigationRun' }])).toBe(true);
    expect(selectsLatestInvestigationRun([{ attribute: 'name' }, { attribute: 'latestInvestigationRun.run_status' }])).toBe(true);
  });

  it('should not select the run for other columns or no column', () => {
    expect(selectsLatestInvestigationRun([{ attribute: 'name' }, { attribute: 'latestInvestigationRunner' }, { attribute: null }])).toBe(false);
    expect(selectsLatestInvestigationRun([])).toBe(false);
    expect(selectsLatestInvestigationRun(null)).toBe(false);
  });
});

describe('Function: isReadThroughNotAllowedObject', () => {
  const instance = {
    name: 'Phishing case',
    objectMarking: [{ id: 'tlp-red' }],
    latestInvestigationRun: {
      objectMarking: [{ id: 'tlp-amber' }],
      report_sections: { report: 'Cited report' },
    },
  };

  it('should withhold a value read through a nested object carrying a marking above the limits', () => {
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun.report_sections.report', ['tlp-amber'])).toEqual(true);
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun.run_status', ['tlp-amber'])).toEqual(true);
  });

  it('should withhold a nested object selected as a whole when it carries a marking above the limits', () => {
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun', ['tlp-amber'])).toEqual(true);
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun', ['tlp-red'])).toEqual(false);
    expect(isReadThroughNotAllowedObject(instance, 'objectMarking', ['tlp-red'])).toEqual(false);
  });

  it('should keep the values of the instance itself and of nested objects within the limits', () => {
    expect(isReadThroughNotAllowedObject(instance, 'name', ['tlp-red'])).toEqual(false);
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun.report_sections.report', ['tlp-red'])).toEqual(false);
    expect(isReadThroughNotAllowedObject(instance, 'latestInvestigationRun.report_sections.report', [])).toEqual(false);
    expect(isReadThroughNotAllowedObject({ latestInvestigationRun: null }, 'latestInvestigationRun.report_sections.report', ['tlp-amber'])).toEqual(false);
  });
});
