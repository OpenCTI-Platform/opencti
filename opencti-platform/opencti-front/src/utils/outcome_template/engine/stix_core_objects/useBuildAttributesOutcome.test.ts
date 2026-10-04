import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../../tests/test-render';
import * as env from '../../../../relay/environment';
import useBuildAttributesOutcome, { isReadThroughNotAllowedObject, selectsLatestInvestigationRun } from './useBuildAttributesOutcome';
import * as filterUtils from '../../../filters/filtersUtils';
import { SELF_ID } from '../../../filters/filtersUtils';

describe('Hook: useBuildAttributesOutcome', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => new Map());
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
    const withheld = await buildAttributesOutcome('id_XX', { instance_id: SELF_ID, columns }, ['tlp-red']);
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
