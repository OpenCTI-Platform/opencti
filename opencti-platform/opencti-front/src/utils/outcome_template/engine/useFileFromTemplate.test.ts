import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import { fetchQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { testRenderHook } from '../../tests/test-render';
import useFileFromTemplate from './useFileFromTemplate';
import * as env from '../../../relay/environment';
import * as useBuildAttributesOutcome from './stix_core_objects/useBuildAttributesOutcome';
import * as useBuildListOutcome from './stix_core_objects/useBuildListOutcome';
import * as filterUtils from '../../filters/filtersUtils';

const buildAttributesOutcomeMock = vi.fn();
const buildListOutcomeMock = vi.fn();
const notifyErrorMock = vi.fn();

describe('Hook: useFileFromTemplate', () => {
  beforeAll(() => {
    vi.spyOn(useBuildAttributesOutcome, 'default').mockImplementation(() => ({
      buildAttributesOutcome: buildAttributesOutcomeMock,
    }));
    vi.spyOn(useBuildListOutcome, 'default').mockImplementation(() => ({
      buildListOutcome: buildListOutcomeMock,
    }));
    vi.spyOn(filterUtils, 'useBuildFiltersForTemplateWidgets').mockImplementation(() => ({
      buildFiltersForTemplateWidgets() {
        return undefined;
      },
    }));
    vi.spyOn(env.MESSAGING$, 'notifyError').mockImplementation(notifyErrorMock);
  });
  beforeEach(() => {
    buildAttributesOutcomeMock.mockReset();
    buildListOutcomeMock.mockReset();
    notifyErrorMock.mockReset();
    buildAttributesOutcomeMock.mockImplementation(async () => {
      return [
        { variableName: 'containerName', attributeData: 'Super report' },
        { variableName: 'containerType', attributeData: 'Report' },
      ];
    });
    buildListOutcomeMock.mockImplementation(async () => {
      return 'my super list of elements';
    });
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should replace attribute widgets with the associated data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useFileFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildFileFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        FintelTemplate() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            fintel_template_widgets: [{
              id: 'XXXX',
              variable_name: 'myAttributes',
              widget: {
                type: 'attribute',
                dataSelection: [{}],
              },
            }],
            template_content: 'Hello, I am container $containerName of type $containerType',
          };
        },
      });
    });

    const content = await buildFileFromTemplate('aaaID', [], 'testTemplate');
    expect(content).toEqual('Hello, I am container Super report of type Report');
  });

  it('should replace attribute lists with corresponding data', async () => {
    const { hook, relayEnv } = testRenderHook(() => useFileFromTemplate());
    // We want fetchQuery function to use the test env of Relay.
    vi.spyOn(env, 'fetchQuery').mockImplementation((q, a) => fetchQuery(relayEnv, q, a ?? {}));
    const { buildFileFromTemplate } = hook.result.current;

    // Fake data returned by the query.
    relayEnv.mock.queueOperationResolver((op) => {
      return MockPayloadGenerator.generate(op, {
        FintelTemplate() {
          return {
            id: 'testTemplate',
            name: 'Test template',
            fintel_template_widgets: [{
              id: 'YYY',
              variable_name: 'containerList',
              widget: {
                type: 'list',
                dataSelection: [{
                  filters: null,
                }],
              },
            }],
            template_content: 'Hello, I have: $containerList',
          };
        },
      });
    });

    const content = await buildFileFromTemplate('aaaID', [], 'testTemplate');
    expect(content).toEqual('Hello, I have: my super list of elements');
  });

  it('should remove an empty template section when explicitly enabled', async () => {
    buildListOutcomeMock.mockImplementation(async () => '');
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'YYY',
          variable_name: 'containerList',
          widget: {
            type: 'list',
            dataSelection: [{
              filters: null,
            }],
          },
        }],
        template_content: '<div><h1>Empty section</h1><p>Items: $containerList</p><h1>Remaining section</h1><p>Body</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Remaining section</h1><p>Body</p></div>');
  });

  it('should preserve legacy output exactly when remove empty sections is disabled', async () => {
    buildListOutcomeMock.mockImplementation(async () => '');
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'YYY',
          variable_name: 'containerList',
          widget: {
            type: 'list',
            dataSelection: [{
              filters: null,
            }],
          },
        }],
        template_content: '<div><h1>Empty section</h1><p>Items: $containerList</p><h1>Remaining section</h1><p>Body</p></div>',
      } as never,
    );

    expect(content).toEqual('<div><h1>Empty section</h1><p>Items: </p><h1>Remaining section</h1><p>Body</p></div>');
  });

  it('should prune empty children before pruning their empty parent section', async () => {
    buildAttributesOutcomeMock.mockImplementation(async () => [
      { variableName: 'parentValue', attributeData: '', isEmpty: true },
      { variableName: 'childValue', attributeData: '', isEmpty: true },
    ]);
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'parentValue', attribute: 'name' },
                { variableName: 'childValue', attribute: 'description' },
              ],
            }],
          },
        }],
        template_content: '<div><section><h1>Parent</h1><p>$parentValue</p><div><h2>Child</h2><p>$childValue</p></div></section><h1>Keep</h1><p>Body</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Keep</h1><p>Body</p></div>');
  });

  it('should keep a parent section when a child section survives', async () => {
    buildAttributesOutcomeMock.mockImplementation(async () => [
      { variableName: 'parentValue', attributeData: '', isEmpty: true },
      { variableName: 'childValue', attributeData: 'populated', isEmpty: false },
    ]);
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'parentValue', attribute: 'name' },
                { variableName: 'childValue', attribute: 'description' },
              ],
            }],
          },
        }],
        template_content: '<div><section><h1>Parent</h1><p>$parentValue</p><div><h2>Child</h2><p>$childValue</p></div></section></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><section><h1>Parent</h1><p></p><div><h2>Child</h2><p>populated</p></div></section></div>');
  });

  it('should respect h1 to h3 boundaries and skipped heading levels', async () => {
    buildAttributesOutcomeMock.mockImplementation(async () => [
      { variableName: 'alpha', attributeData: '', isEmpty: true },
      { variableName: 'beta', attributeData: 'beta value', isEmpty: false },
      { variableName: 'gamma', attributeData: '', isEmpty: true },
    ]);
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'alpha', attribute: 'name' },
                { variableName: 'beta', attribute: 'description' },
                { variableName: 'gamma', attribute: 'created_at' },
              ],
            }],
          },
        }],
        template_content: '<div><h1>Alpha</h1><p>$alpha</p><h3>Beta</h3><p>$beta</p><h2>Gamma</h2><p>$gamma</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Alpha</h1><p></p><h3>Beta</h3><p>beta value</p></div>');
  });

  it('should remove wrapped sections and adjacent page breaks with them', async () => {
    buildListOutcomeMock.mockImplementation(async () => '');
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'LIST',
          variable_name: 'containerList',
          widget: {
            type: 'list',
            dataSelection: [{ filters: null }],
          },
        }],
        template_content: '<div><div class="wrapper"><h1>Section</h1><div><p>$containerList</p><div class="page-break"></div></div></div><div><h1>Tail</h1><p>Tail</p></div></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><div><h1>Tail</h1><p>Tail</p></div></div>');
  });

  it('should preserve static-only sections and parents with surviving static-only children', async () => {
    buildAttributesOutcomeMock.mockImplementation(async () => [
      { variableName: 'parentValue', attributeData: '', isEmpty: true },
    ]);
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'parentValue', attribute: 'name' },
              ],
            }],
          },
        }],
        template_content: '<div><h1>Parent</h1><p>$parentValue</p><h2>Static child</h2><p>Always keep me</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Parent</h1><p></p><h2>Static child</h2><p>Always keep me</p></div>');
  });

  it('should keep sections with unresolved or failed variables', async () => {
    buildListOutcomeMock.mockImplementationOnce(async () => {
      throw new Error('boom');
    });
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'LIST',
          variable_name: 'containerList',
          widget: {
            type: 'list',
            dataSelection: [{ filters: null }],
          },
        }],
        template_content: '<div><h1>Errored</h1><p>$containerList</p><h1>Unknown</h1><p>$unknownToken</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toContain('<h1>Errored</h1>');
    expect(content).toContain('An error occurred while retrieving data for this widget:');
    expect(content).toContain('<h1>Unknown</h1><p>$unknownToken</p>');
  });

  it('should not confuse repeated or prefixed variable names', async () => {
    buildAttributesOutcomeMock.mockImplementation(async () => [
      { variableName: 'name', attributeData: '', isEmpty: true },
      { variableName: 'name_long', attributeData: 'long value', isEmpty: false },
    ]);
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'name', attribute: 'name' },
                { variableName: 'name_long', attribute: 'description' },
              ],
            }],
          },
        }],
        template_content: '<div><h1>Short</h1><p>$name</p><h1>Long</h1><p>$name_long and again $name_long</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Long</h1><p>long value and again long value</p></div>');
  });

  it('should ignore headings inserted by widget content when building template sections', async () => {
    buildListOutcomeMock.mockImplementation(async () => '<h1>Widget heading</h1><p>Widget body</p>');
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'LIST',
          variable_name: 'containerList',
          widget: {
            type: 'list',
            dataSelection: [{ filters: null }],
          },
        }],
        template_content: '<div><h1>Template section</h1><div>$containerList</div><h1>Next</h1><p>Body</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Template section</h1><div><h1>Widget heading</h1><p>Widget body</p></div><h1>Next</h1><p>Body</p></div>');
  });

  it('should preserve legacy attribute replacement while keeping errored metadata sections when pruning is enabled', async () => {
    buildAttributesOutcomeMock.mockImplementation(async (_containerId, _dataSelection, options) => {
      if (options?.includeMetadata) {
        throw new Error('Invalid path "createdBy.name", a subpart is not an object');
      }

      return [{ variableName: 'createdByName', attributeData: '', isEmpty: false }];
    });
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const template = {
      id: 'testTemplate',
      name: 'Test template',
      fintel_template_widgets: [{
        id: 'ATTR',
        variable_name: 'attributes',
        widget: {
          type: 'attribute',
          dataSelection: [{
            columns: [{ variableName: 'createdByName', attribute: 'createdBy.name' }],
          }],
        },
      }],
      template_content: '<div><h1>Broken</h1><p>$createdByName</p><h1>Keep</h1><p>Body</p></div>',
    } as never;

    const legacyContent = await buildFileFromTemplate('aaaID', [], undefined, template);
    const prunedContent = await buildFileFromTemplate('aaaID', [], undefined, template, { removeEmptySections: true });

    expect(legacyContent).toEqual('<div><h1>Broken</h1><p></p><h1>Keep</h1><p>Body</p></div>');
    expect(prunedContent).toContain('<h1>Broken</h1><p>$createdByName</p>');
    expect(prunedContent).toContain('<h1>Keep</h1><p>Body</p>');
  });

  it('should keep valid metadata attributes, preserve unresolved bad columns, and notify through messaging', async () => {
    buildAttributesOutcomeMock.mockImplementation(async (_containerId, _dataSelection, options) => {
      if (!options?.includeMetadata) {
        return [
          { variableName: 'reportName', attributeData: 'Super report', isEmpty: false },
          { variableName: 'createdByName', attributeData: '', isEmpty: false },
        ];
      }

      return [
        { variableName: 'reportName', attributeData: 'Super report', isEmpty: false },
        {
          variableName: 'createdByName',
          attributeData: '$createdByName',
          isEmpty: false,
          preserveSection: true,
          error: 'Invalid path "createdBy.name", a subpart is not an object',
        },
      ];
    });
    const { hook } = testRenderHook(() => useFileFromTemplate());
    const { buildFileFromTemplate } = hook.result.current;

    const content = await buildFileFromTemplate(
      'aaaID',
      [],
      undefined,
      {
        id: 'testTemplate',
        name: 'Test template',
        fintel_template_widgets: [{
          id: 'ATTR',
          variable_name: 'attributes',
          widget: {
            type: 'attribute',
            dataSelection: [{
              columns: [
                { variableName: 'reportName', attribute: 'name' },
                { variableName: 'createdByName', attribute: 'createdBy.name' },
              ],
            }],
          },
        }],
        template_content: '<div><h1>Summary</h1><p>$reportName</p><h1>Author</h1><p>$createdByName</p></div>',
      } as never,
      { removeEmptySections: true },
    );

    expect(content).toEqual('<div><h1>Summary</h1><p>Super report</p><h1>Author</h1><p>$createdByName</p></div>');
    expect(notifyErrorMock).toHaveBeenCalledWith('One of the attribute widgets resolution raised an error. Invalid path "createdBy.name", a subpart is not an object');
  });
});
