import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  internalFindByIdsMapped: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/modules/fintelTemplate/fintelTemplate-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/fintelTemplate/fintelTemplate-domain')>()),
  addFintelTemplate: vi.fn(),
  fintelTemplateEditField: vi.fn(),
}));
// The ids of the filters are converted by the workspace utilities, which read the platform: their conversion is checked there
vi.mock('../../../../src/modules/workspace/workspace-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/workspace/workspace-utils')>()),
  convertWidgetsIds: vi.fn(),
}));

import { fullEntitiesList, internalFindByIdsMapped, storeLoadById } from '../../../../src/database/middleware-loader';
import { addFintelTemplate, fintelTemplateEditField } from '../../../../src/modules/fintelTemplate/fintelTemplate-domain';
import { convertWidgetsIds } from '../../../../src/modules/workspace/workspace-utils';
import { exportFintelTemplateToBundle } from '../../../../src/modules/fintelTemplate/fintelTemplate-export';
import { importFintelTemplate } from '../../../../src/modules/fintelTemplate/fintelTemplate-import';
import { FINTEL_TEMPLATE_NAME_MAX_LENGTH, fintelTemplateImportSchema } from '../../../../src/modules/fintelTemplate/fintelTemplate-import-schema';
import type { BasicStoreEntityFintelTemplate } from '../../../../src/modules/fintelTemplate/fintelTemplate-types';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { groupingFintelTemplate, reportFintelTemplate } from '../configPreset/configPreset-fintelTemplates-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };
const copy = { mode: ConfigImportMode.Copy };

const withExisting = (template?: BasicStoreEntityFintelTemplate) => vi.mocked(storeLoadById).mockResolvedValue(template as never);
// The templates the platform has, found by their entity type and their name
const withTemplates = (...templates: BasicStoreEntityFintelTemplate[]) => vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, _types, args) => {
  const filters = (args as { filters: { filters: { key: string[]; values: string[] }[] } }).filters.filters;
  const value = (key: string) => filters.find((filter) => filter.key[0] === key)?.values[0];
  return templates.filter((template) => template.settings_types[0] === value('settings_types') && template.name === value('name')) as never;
});
const editInput = () => vi.mocked(fintelTemplateEditField).mock.calls[0][3];
const addInput = (call = 0) => vi.mocked(addFintelTemplate).mock.calls[call][2];

let configuration: Record<string, unknown>;

beforeEach(async () => {
  vi.resetAllMocks();
  withExisting();
  withTemplates();
  configuration = await exportFintelTemplateToBundle(context, user, reportFintelTemplate);
});

describe('Fintel template import schema', () => {
  it('takes back what the export writes, a template of another type without description nor widget included', async () => {
    expect(fintelTemplateImportSchema.safeParse(configuration).success).toBe(true);
    expect(fintelTemplateImportSchema.safeParse(await exportFintelTemplateToBundle(context, user, groupingFintelTemplate)).success).toBe(true);
    // Only the standard id, the name and the entity type are required
    expect(fintelTemplateImportSchema.safeParse({ standard_id: reportFintelTemplate.standard_id, name: 'Brief', settings_types: ['Report'] }).success).toBe(true);
  });

  it('refuses unknown keys, another standard id, a name too short or too long, other than one entity type, a start date that is not a date and a widget without data selection', () => {
    const refuses = (changes: Record<string, unknown>) => expect(fintelTemplateImportSchema.safeParse({ ...configuration, ...changes }).success).toBe(false);
    refuses({ id: 'report-fintel-template-id' });
    refuses({ standard_id: 'customview--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b' });
    refuses({ name: ' a ' });
    refuses({ name: 'n'.repeat(FINTEL_TEMPLATE_NAME_MAX_LENGTH + 1) });
    refuses({ settings_types: [] });
    refuses({ settings_types: ['Report', 'Grouping'] });
    refuses({ start_date: 'yesterday' });
    refuses({ fintel_template_widgets: [{ variable_name: 'widget', widget: { type: 'list' } }] });
  });

  it('refuses a widget the editor cannot open or whose filters would be stored as text: no data selection, filters that are not an object', () => {
    const withSelection = (selection: Record<string, unknown>[]) => ({
      ...configuration,
      fintel_template_widgets: [{ variable_name: 'widget', widget: { type: 'list', dataSelection: selection } }],
    });
    const parses = (selection: Record<string, unknown>[]) => fintelTemplateImportSchema.safeParse(withSelection(selection)).success;
    expect(parses([])).toBe(false);
    expect(parses([{ filters: '{"mode":"and","filters":[],"filterGroups":[]}' }])).toBe(false);
    expect(parses([{ dynamicFrom: [] }])).toBe(false);
    expect(parses([{ dynamicTo: 1 }])).toBe(false);
    // The instance an attribute widget shows and its columns, read by the platform without checking
    expect(parses([{ instance_id: 123 }])).toBe(false);
    expect(parses([{ columns: {} }])).toBe(false);
    expect(parses([{ columns: [null] }])).toBe(false);
    expect(parses([{ columns: [{ label: 'Name', variableName: 1 }] }])).toBe(false);
    expect(parses([{ instance_id: null, columns: null }])).toBe(true);
    // No filter, or none written: a widget of attributes of the instance has none
    expect(parses([{ filters: null, dynamicFrom: undefined }, { instance_id: 'SELF_ID' }])).toBe(true);
  });
});

describe('Fintel template widgets: the instance an attribute widget shows', () => {
  const REPORT = { internal_id: 'report-internal-id', standard_id: 'report--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b' };
  // The platform knows the report by every id it has
  const withReport = () => vi.mocked(internalFindByIdsMapped).mockResolvedValue({ [REPORT.internal_id]: REPORT, [REPORT.standard_id]: REPORT } as never);
  const attributesOf = (...instanceIds: string[]) => instanceIds.map((instanceId, i) => ({
    variable_name: `attributes${i}`,
    widget: { id: `widget-${i}`, type: 'attribute', perspective: null, dataSelection: [{ instance_id: instanceId, columns: [], filters: '{}' }], parameters: {} },
  }));
  const instanceIdsOf = (widgets: { widget: { dataSelection: { instance_id?: unknown }[] } }[] | undefined) => (widgets ?? [])
    .map(({ widget }) => widget.dataSelection[0].instance_id);

  it('exports a given instance by its standard id, keeps the instance the template is applied to and an unknown one as they are', async () => {
    withReport();
    const template = { ...reportFintelTemplate, fintel_template_widgets: attributesOf('report-internal-id', 'SELF_ID', 'deleted-entity-id') } as unknown as BasicStoreEntityFintelTemplate;
    const exported = await exportFintelTemplateToBundle(context, user, template);
    expect(instanceIdsOf(exported.fintel_template_widgets as never)).toEqual([REPORT.standard_id, 'SELF_ID', 'deleted-entity-id']);
    // Only the given instances are looked up, once each
    expect(internalFindByIdsMapped).toHaveBeenCalledWith(context, user, ['report-internal-id', 'deleted-entity-id'], { baseData: true, mapWithAllIds: true });
    // The template itself is untouched
    expect(instanceIdsOf(template.fintel_template_widgets as never)).toEqual(['report-internal-id', 'SELF_ID', 'deleted-entity-id']);
  });

  it('imports a given instance by its id on this platform, keeps the instance the template is applied to and an unknown one as they are', async () => {
    withReport();
    const widgets = attributesOf(REPORT.standard_id, 'SELF_ID', 'report--00000000-0000-4000-8000-000000000000')
      .map(({ variable_name, widget }) => ({ variable_name, widget: { ...widget, dataSelection: widget.dataSelection.map((selection) => ({ ...selection, filters: {} })) } }));
    await importFintelTemplate(context, user, { ...configuration, fintel_template_widgets: widgets }, overwrite);
    expect(instanceIdsOf(addInput().fintel_template_widgets as never)).toEqual(['report-internal-id', 'SELF_ID', 'report--00000000-0000-4000-8000-000000000000']);
  });

  it('looks nothing up when every widget shows the instance the template is applied to', async () => {
    await exportFintelTemplateToBundle(context, user, reportFintelTemplate);
    await importFintelTemplate(context, user, configuration, overwrite);
    expect(internalFindByIdsMapped).not.toHaveBeenCalled();
  });
});

describe('Fintel template import', () => {
  it('refuses an invalid configuration, or widgets the platform refuses, without writing anything', async () => {
    expect(await importFintelTemplate(context, user, { ...configuration, name: '' }, overwrite)).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    const spaced = [{ variable_name: 'my widget', widget: { type: 'list', dataSelection: [{}] } }];
    expect(await importFintelTemplate(context, user, { ...configuration, fintel_template_widgets: spaced }, overwrite)).toMatchObject({
      status: 'failed',
      code: 'invalid',
      reason: 'Variable names should not contain spaces or special chars (except - and _)',
    });
    expect(addFintelTemplate).not.toHaveBeenCalled();
  });

  it('creates a template that does not exist under its standard id, as the default of its type, with its widgets only, and writes nothing on a dry run', async () => {
    expect(await importFintelTemplate(context, user, configuration, { ...overwrite, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(addFintelTemplate).not.toHaveBeenCalled();

    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'created', exists: false });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, reportFintelTemplate.standard_id, 'FintelTemplate');
    // The built-in widgets of a new template are not added: an exported template has them already
    expect(vi.mocked(addFintelTemplate).mock.calls[0][3]).toBe(true);
    expect(addInput()).toEqual({
      standard_id: reportFintelTemplate.standard_id,
      name: 'Executive Summary',
      settings_types: ['Report'],
      description: 'The summary of a report',
      instance_filters: undefined,
      template_content: '<p>$containerRepresentative</p>',
      start_date: '2026-01-02T00:00:00.000Z',
      default: true,
      include_cover_page_by_default: true,
      include_back_page_by_default: false,
      // The filters as the platform stores them, with its ids
      fintel_template_widgets: [{
        variable_name: 'widgetSelfAttributes',
        widget: expect.objectContaining({
          type: 'attribute',
          dataSelection: [expect.objectContaining({ instance_id: 'SELF_ID', filters: '{}', dynamicFrom: '{}', dynamicTo: '{}' })],
        }),
      }],
    });
    expect(convertWidgetsIds).toHaveBeenCalledWith(context, user, expect.any(Array), 'stix');
    // The configuration of the result stays the one of the bundle
    const bundleSelection = expect.objectContaining({ filters: {} });
    expect(configuration.fintel_template_widgets).toEqual([expect.objectContaining({ widget: expect.objectContaining({ dataSelection: [bundleSelection] }) })]);
  });

  it('refuses a widget with the reason of what it breaks: its variables, or filters the conversion cannot walk, and fails on any other error', async () => {
    const attributes = (columns: unknown[]) => [{ variable_name: 'attributes', widget: { type: 'attribute', dataSelection: [{ instance_id: 'SELF_ID', columns }] } }];
    expect(await importFintelTemplate(context, user, { ...configuration, fintel_template_widgets: attributes([{ label: 'Name', attribute: 'name' }]) }, overwrite))
      .toMatchObject({ status: 'failed', code: 'invalid', reason: 'Attributes should all have a variable name' });
    // Refused before any conversion of its filters
    expect(vi.mocked(convertWidgetsIds).mock.calls.filter(([, , , from]) => from === 'stix')).toHaveLength(0);

    vi.mocked(convertWidgetsIds).mockRejectedValueOnce(new TypeError('Cannot read properties of undefined'));
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'failed', code: 'invalid', reason: 'The filters of the widgets are malformed' });
    // A failure of the platform is not the item's: it stays an error
    vi.mocked(convertWidgetsIds).mockRejectedValueOnce(new Error('Elasticsearch timeout'));
    await expect(importFintelTemplate(context, user, configuration, overwrite)).rejects.toThrow('Elasticsearch timeout');
    expect(addFintelTemplate).not.toHaveBeenCalled();
  });

  it('stores no filter for a selection that has none, never the text of a null', async () => {
    const widgets = [{ variable_name: 'widget', widget: { type: 'list', dataSelection: [{ filters: null, dynamicFrom: { mode: 'and', filters: [], filterGroups: [] } }] } }];
    await importFintelTemplate(context, user, { ...configuration, fintel_template_widgets: widgets }, overwrite);
    const [selection] = addInput().fintel_template_widgets![0].widget.dataSelection;
    expect(selection).toMatchObject({ filters: undefined, dynamicTo: undefined, dynamicFrom: '{"mode":"and","filters":[],"filterGroups":[]}' });
  });

  it('skips a built-in template exported and imported as it is: a selection without filter is the empty filter group the export writes', async () => {
    const builtIn = {
      ...reportFintelTemplate,
      fintel_template_widgets: [{
        variable_name: 'widgetSelfAttributes',
        widget: { id: 'built-in-widget-id', type: 'attribute', perspective: null, dataSelection: [{ instance_id: 'SELF_ID', columns: [] }], parameters: { title: 'Attributes' } },
      }],
    } as unknown as BasicStoreEntityFintelTemplate;
    withExisting(builtIn);
    const exported = await exportFintelTemplateToBundle(context, user, builtIn);
    expect(exported.fintel_template_widgets![0].widget.dataSelection[0]).toMatchObject({ filters: {}, dynamicFrom: {}, dynamicTo: {} });
    expect(await importFintelTemplate(context, user, exported, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
  });

  it('creates a template whatever the names of the others, two templates can have the same name, and says so when its entity type has one', async () => {
    const sameName = 'A template with the same name already exists in its entity type';
    const otherPlatform = { ...configuration, standard_id: 'finteltemplate--00000000-0000-5000-8000-000000000000' };
    withTemplates(reportFintelTemplate);
    expect(await importFintelTemplate(context, user, otherPlatform, overwrite)).toMatchObject({ status: 'created', exists: false, reason: sameName });
    expect(addInput()).toMatchObject({ name: 'Executive Summary', standard_id: 'finteltemplate--00000000-0000-5000-8000-000000000000' });
    // A copy of a template that does not exist keeps its name as well
    expect(await importFintelTemplate(context, user, otherPlatform, copy)).toMatchObject({ status: 'created', exists: false, copyName: 'Executive Summary', reason: sameName });
    // The same name in another entity type is another name
    expect(await importFintelTemplate(context, user, { ...otherPlatform, settings_types: ['Grouping'] }, overwrite)).toMatchObject({ status: 'created', reason: undefined });

    // Two items of the same import that take the same name: the second one says so in the preview, as the real import creates both
    withTemplates();
    const reservedNames = new Set<string>();
    expect(await importFintelTemplate(context, user, configuration, { ...overwrite, dryRun: true, reservedNames })).toMatchObject({ reason: undefined });
    expect(await importFintelTemplate(context, user, otherPlatform, { ...overwrite, dryRun: true, reservedNames })).toMatchObject({ reason: sameName });
  });

  it('refuses a template of an entity type that has no FINTEL templates, a type of a newer platform included, without reading nor writing anything', async () => {
    for (const settingsType of ['Indicator', 'Foo']) {
      expect(await importFintelTemplate(context, user, { ...configuration, settings_types: [settingsType] }, overwrite)).toMatchObject({
        status: 'failed',
        code: 'entity_type',
        reason: 'FINTEL templates are not available for this entity type',
        exists: false,
      });
    }
    expect(storeLoadById).not.toHaveBeenCalled();
    expect(addFintelTemplate).not.toHaveBeenCalled();
  });

  it('says whether the template already is the default of its entity type here, whatever the import does', async () => {
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'created', existsAsDefault: false });
    withExisting(reportFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'skipped', existsAsDefault: true });
    expect(await importFintelTemplate(context, user, configuration, copy)).toMatchObject({ status: 'created', existsAsDefault: true });
    withExisting({ ...reportFintelTemplate, default: false } as BasicStoreEntityFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'overwritten', existsAsDefault: false });
  });

  it('refuses a template that exists when it is added', async () => {
    withExisting(reportFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
  });

  it('skips a template the platform has as it is, whatever the ids of its widgets and the writing of its filters', async () => {
    const stored = {
      ...reportFintelTemplate,
      fintel_template_widgets: reportFintelTemplate.fintel_template_widgets.map(({ variable_name, widget }) => ({
        variable_name,
        widget: { ...widget, id: 'another-widget-id', dataSelection: widget.dataSelection.map((selection) => ({ ...selection, filters: '{ }' })) },
      })),
    } as BasicStoreEntityFintelTemplate;
    withExisting(stored);
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(fintelTemplateEditField).not.toHaveBeenCalled();
  });

  it('overwrites what differs, the widgets as a whole, and makes the template the default of its type', async () => {
    withExisting({
      ...reportFintelTemplate,
      name: 'Old name',
      description: 'Old description',
      start_date: null,
      default: false,
      include_back_page_by_default: true,
      fintel_template_widgets: [],
    } as unknown as BasicStoreEntityFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, { ...overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(fintelTemplateEditField).not.toHaveBeenCalled();
    expect(await importFintelTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'overwritten', exists: true });
    expect(vi.mocked(fintelTemplateEditField).mock.calls[0][2]).toBe(reportFintelTemplate.id);
    expect(editInput().map(({ key }) => key)).toEqual(['name', 'description', 'start_date', 'include_back_page_by_default', 'fintel_template_widgets', 'default']);
    expect(editInput()).toContainEqual({ key: 'start_date', value: ['2026-01-02T00:00:00.000Z'] });
    expect(editInput()).toContainEqual({ key: 'default', value: [true] });
  });

  it('writes what the bundle empties, unpublishes the template, leaves a key the bundle does not have untouched, and never takes the default away', async () => {
    withExisting(reportFintelTemplate);
    const { template_content: _, fintel_template_widgets: __, ...partial } = configuration;
    await importFintelTemplate(context, user, { ...partial, description: null, start_date: null, default: false }, overwrite);
    expect(editInput()).toEqual([{ key: 'description', value: [null] }, { key: 'start_date', value: [null] }]);
  });

  it('refuses to move a template to another entity type', async () => {
    withExisting(reportFintelTemplate);
    expect(await importFintelTemplate(context, user, { ...configuration, settings_types: ['Grouping'] }, overwrite)).toMatchObject({
      status: 'failed',
      code: 'entity_type',
      reason: 'The entity type of the fintel template cannot change',
      exists: true,
    });
    expect(fintelTemplateEditField).not.toHaveBeenCalled();
  });

  it('copies a template that exists under a free name of its entity type and a new standard id, never as the default of its type', async () => {
    withExisting(reportFintelTemplate);
    // The same name in another entity type does not take it
    withTemplates(reportFintelTemplate, { ...groupingFintelTemplate, name: 'Executive Summary (1)' } as BasicStoreEntityFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, { ...copy, dryRun: true })).toMatchObject({
      status: 'created',
      exists: true,
      copyName: 'Executive Summary (1)',
      reason: 'Added as "Executive Summary (1)"',
    });
    expect(addFintelTemplate).not.toHaveBeenCalled();
    await importFintelTemplate(context, user, configuration, copy);
    expect(addInput()).toMatchObject({ name: 'Executive Summary (1)', default: false });
    expect(addInput()).not.toHaveProperty('standard_id');
  });

  it('copies a template that does not exist under its own name and standard id, the default of its type when it is the default of the bundle', async () => {
    expect(await importFintelTemplate(context, user, configuration, copy)).toMatchObject({ status: 'created', exists: false, copyName: 'Executive Summary', reason: undefined });
    expect(addInput()).toMatchObject({ name: 'Executive Summary', standard_id: reportFintelTemplate.standard_id, default: true });
  });

  it('keeps the free name of a copy within the length of a name, and refuses the copy when every free name is taken', async () => {
    const longName = 'n'.repeat(FINTEL_TEMPLATE_NAME_MAX_LENGTH);
    const long = { ...reportFintelTemplate, name: longName } as BasicStoreEntityFintelTemplate;
    withExisting(long);
    withTemplates(long);
    expect((await importFintelTemplate(context, user, { ...configuration, name: longName }, copy)).copyName).toBe(`${'n'.repeat(FINTEL_TEMPLATE_NAME_MAX_LENGTH - 4)} (1)`);

    vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, _types, args) => {
      const filters = (args as { filters: { filters: { key: string[]; values: string[] }[] } }).filters.filters;
      return [{ ...reportFintelTemplate, id: 'other', name: filters.find(({ key }) => key[0] === 'name')?.values[0] }] as never;
    });
    expect(await importFintelTemplate(context, user, configuration, copy)).toMatchObject({ status: 'failed', code: 'name_conflict', reason: 'Fintel template name already exists' });
  });

  it('gives a copy the name the real import will give it, after a template an earlier item of the dry run creates or renames', async () => {
    const reservedNames = new Set<string>();
    const renamedIds = new Set<string>();
    const dryRun = { dryRun: true, reservedNames, renamedIds };
    withTemplates(reportFintelTemplate);
    // A new template of the reports takes "Executive Summary (1)": the copy of the existing "Executive Summary" after it cannot take it
    const created = { ...configuration, standard_id: 'finteltemplate--00000000-0000-5000-8000-000000000000', name: 'Executive Summary (1)', default: false };
    await importFintelTemplate(context, user, created, { ...overwrite, ...dryRun });
    withExisting(reportFintelTemplate);
    expect(await importFintelTemplate(context, user, configuration, { ...copy, ...dryRun })).toMatchObject({ copyName: 'Executive Summary (2)' });

    // A template renamed by an earlier item no longer holds its name
    reservedNames.clear();
    await importFintelTemplate(context, user, { ...configuration, name: 'Board summary' }, { ...overwrite, ...dryRun });
    expect(renamedIds).toEqual(new Set([reportFintelTemplate.id]));
    expect(await importFintelTemplate(context, user, configuration, { ...copy, ...dryRun })).toMatchObject({ copyName: 'Executive Summary', reason: undefined });
    expect(addFintelTemplate).not.toHaveBeenCalled();
    expect(fintelTemplateEditField).not.toHaveBeenCalled();
  });
});
