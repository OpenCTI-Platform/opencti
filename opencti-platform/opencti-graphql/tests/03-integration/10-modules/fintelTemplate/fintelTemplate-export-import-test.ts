import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { buildZip, itemFile, metadataFile } from '../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as enterpriseEdition from '../../../../src/enterprise-edition/ee';
import { getClientBase } from '../../../../src/database/redis';
import { deleteFile } from '../../../../src/database/file-storage';
import { downloadFile } from '../../../../src/database/raw-file-storage';
import { fullEntitiesList, internalLoadById } from '../../../../src/database/middleware-loader';
import { allFilesForPaths } from '../../../../src/modules/internal/document/document-domain';
import { MARKING_TLP_GREEN } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import type { BasicStoreEntityMarkingDefinition } from '../../../../src/types/store';
import { addFintelTemplate, fintelTemplateDelete, fintelTemplateEditField } from '../../../../src/modules/fintelTemplate/fintelTemplate-domain';
import { type BasicStoreEntityFintelTemplate, ENTITY_TYPE_FINTEL_TEMPLATE } from '../../../../src/modules/fintelTemplate/fintelTemplate-types';

// The real export and the real import engine on the fintel templates: a template is found by its standard id, its widgets point to what they
// filter by its standard id in the zip and by its id on the platform, and the default of an entity type is the one of the bundle.
// Names that no other test of the platform uses.
const PREFIX = 'Config preset round trip template';
const REPORT_NAME = `${PREFIX} report`;
const GROUPING_NAME = `${PREFIX} grouping`;
const TARGET_DEFAULT_NAME = `${PREFIX} target default`;

const UPLOAD_MUTATION = gql`mutation FintelTemplateRoundTripUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const EXPORT_MUTATION = gql`mutation FintelTemplateRoundTripExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }`;
const IMPORT_MUTATION = gql`
  mutation FintelTemplateRoundTripImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results { type key status code reason label }
    }
  }
`;
const PARTIAL_PREVIEW_MUTATION = gql`
  mutation FintelTemplatePartialPreview($file: Upload!, $type: ID!, $scope: String) {
    configPresetPartialImportPreview(file: $file, type: $type, scope: $scope) {
      default_mode
      type { key items { key label exists conflict isDefault } }
    }
  }
`;
const PARTIAL_IMPORT_MUTATION = gql`
  mutation FintelTemplatePartialImport($file: Upload!, $type: ID!, $items: [ID!]!, $scope: String) {
    configPresetPartialImport(file: $file, type: $type, items: $items, scope: $scope) {
      results { type key status reason label }
    }
  }
`;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const allTemplates = () => fullEntitiesList<BasicStoreEntityFintelTemplate>(testContext, ADMIN_USER, [ENTITY_TYPE_FINTEL_TEMPLATE]);
const templatesNamed = async (name: string) => (await allTemplates()).filter((template) => template.name === name);
const loadTemplate = async (name: string) => (await templatesNamed(name))[0];
const defaultsOf = async (settingsType: string) => (await allTemplates())
  .filter((template) => template.default && template.settings_types[0] === settingsType)
  .map((template) => template.name);
const deleteTestTemplates = async () => {
  for (const template of (await allTemplates()).filter(({ name }) => name.startsWith(PREFIX))) {
    await fintelTemplateDelete(testContext, ADMIN_USER, template.id);
  }
};
// A widget that lists the reports marked TLP:GREEN: its filter points to the marking by its id
const markedWidget = (markingId: string) => ({
  variable_name: 'greenReports',
  widget: {
    type: 'list',
    perspective: 'entities',
    dataSelection: [{
      label: 'Green reports',
      number: 10,
      filters: JSON.stringify({ mode: 'and', filters: [{ key: ['objectMarking'], values: [markingId], operator: 'eq', mode: 'or' }], filterGroups: [] }),
      dynamicFrom: JSON.stringify({}),
      dynamicTo: JSON.stringify({}),
    }],
    parameters: { title: 'Green reports' },
  },
});
// A widget of the attributes of a given report, not of the instance the template is applied to: it points to the report by its id
const reportAttributesWidget = (reportId: string) => ({
  variable_name: 'givenReport',
  widget: {
    type: 'attribute',
    perspective: null,
    dataSelection: [{ instance_id: reportId, columns: [{ label: 'Name', attribute: 'name', variableName: 'givenReportName' }] }],
    parameters: { title: 'A given report' },
  },
});
const instanceIdOf = (template: BasicStoreEntityFintelTemplate) => {
  const widgets: { variable_name: string; widget: { dataSelection: { instance_id?: string | null }[] } }[] = template.fintel_template_widgets;
  return widgets.find(({ variable_name }) => variable_name === 'givenReport')?.widget.dataSelection[0].instance_id;
};
const markingValueOf = (template: BasicStoreEntityFintelTemplate) => JSON.parse(template.fintel_template_widgets[0].widget.dataSelection[0].filters as string).filters[0].values[0];
const runImport = async (zip: Buffer, selections: unknown[], dryRun: boolean) => {
  const uploaded = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(zip, 'fintel-templates.zip') } });
  const { data, errors } = await queryAsAdmin({
    query: IMPORT_MUTATION,
    variables: { file_id: uploaded.data?.configPresetImportUpload.id, selections, dry_run: dryRun },
  });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; code: string | null; reason: string | null; label: string }[];
};
const exportBundle = async (selections: unknown[]) => {
  const exported = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections } });
  const exportId = exported.data?.configPresetExport.id as string;
  const bundle = await readStream(await downloadFile(exportId));
  await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
  const directory = await unzipper.Open.buffer(bundle);
  const files: Record<string, Buffer> = {};
  for (let i = 0; i < directory.files.length; i += 1) {
    files[directory.files[i].path] = await directory.files[i].buffer();
  }
  return { bundle, files };
};
const templatePath = (template: BasicStoreEntityFintelTemplate) => `customization/fintel_templates/${template.standard_id}.json`;

describe('Fintel templates: export and import of the real zip', () => {
  let green: { id: string; standard_id: string };
  let givenReport: { id: string; standard_id: string };

  beforeAll(async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
    green = await internalLoadById<BasicStoreEntityMarkingDefinition>(testContext, ADMIN_USER, MARKING_TLP_GREEN);
    [givenReport] = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], { first: 1 });
  });

  afterAll(async () => {
    await deleteTestTemplates();
    vi.restoreAllMocks();
  });

  afterEach(async () => {
    await queryAsAdmin({ query: gql`mutation FintelTemplateRoundTripClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('exports the templates selected with their widgets by standard ids, imports them as they were, the default one as the default of its type', async () => {
    await addFintelTemplate(testContext, ADMIN_USER, {
      name: REPORT_NAME,
      settings_types: ['Report'],
      description: 'Round trip',
      template_content: '<p>$greenReports</p>',
      start_date: '2026-01-02T00:00:00.000Z',
      default: true,
      include_back_page_by_default: false,
      fintel_template_widgets: [markedWidget(green.id), reportAttributesWidget(givenReport.id)],
    }, true);
    await addFintelTemplate(testContext, ADMIN_USER, { name: GROUPING_NAME, settings_types: ['Grouping'], default: false }, true);
    const report = await loadTemplate(REPORT_NAME);
    const grouping = await loadTemplate(GROUPING_NAME);

    // Only the template of the reports is selected: the other one is left out
    const onlyReport = await exportBundle([{ type: 'fintelTemplates', items: [report.standard_id] }]);
    expect(Object.keys(onlyReport.files).sort()).toEqual([templatePath(report), 'dependencies.json', 'metadata.json'].sort());
    // The widget points to the marking by its standard id: the same on every platform
    const exported = JSON.parse(onlyReport.files[templatePath(report)].toString());
    expect(exported.configuration).toMatchObject({ standard_id: report.standard_id, name: REPORT_NAME, settings_types: ['Report'], default: true });
    expect(exported.configuration.fintel_template_widgets[0].widget.dataSelection[0].filters.filters[0].values).toEqual([green.standard_id]);
    // The given report of an attribute widget too
    expect(exported.configuration.fintel_template_widgets[1].widget.dataSelection[0].instance_id).toBe(givenReport.standard_id);

    const { bundle: zip } = await exportBundle([{ type: 'fintelTemplates', items: [report.standard_id, grouping.standard_id] }]);

    // Another platform: the templates do not exist there, and the reports have their own default template
    await fintelTemplateDelete(testContext, ADMIN_USER, report.id);
    await fintelTemplateDelete(testContext, ADMIN_USER, grouping.id);
    await addFintelTemplate(testContext, ADMIN_USER, { name: TARGET_DEFAULT_NAME, settings_types: ['Report'], default: true }, true);

    const selections = [{ type: 'fintelTemplates' }];
    const dry = await runImport(zip, selections, true);
    // By name
    expect(dry.map(({ label, status }) => [label, status])).toEqual([[`${GROUPING_NAME} (Grouping)`, 'CREATED'], [`${REPORT_NAME} (Report)`, 'CREATED']]);
    expect(await templatesNamed(REPORT_NAME)).toHaveLength(0);

    const real = await runImport(zip, selections, false);
    expect(real.map(({ status }) => status)).toEqual(['CREATED', 'CREATED']);
    const restored = await loadTemplate(REPORT_NAME);
    expect(restored).toMatchObject({
      standard_id: report.standard_id,
      description: 'Round trip',
      template_content: '<p>$greenReports</p>',
      default: true,
      include_back_page_by_default: false,
    });
    expect(new Date(restored.start_date).toISOString()).toBe('2026-01-02T00:00:00.000Z');
    // The widgets point to the marking and to the given report by their ids on this platform again
    expect(markingValueOf(restored)).toBe(green.id);
    expect(instanceIdOf(restored)).toBe(givenReport.id);
    expect(await loadTemplate(GROUPING_NAME)).toMatchObject({ standard_id: grouping.standard_id, default: false });
    // The default template of the bundle is the only default of its entity type
    expect(await defaultsOf('Report')).toEqual([REPORT_NAME]);

    const again = await runImport(zip, selections, false);
    expect(again.map(({ status, code }) => `${status}:${code}`)).toEqual(['SKIPPED:unchanged', 'SKIPPED:unchanged']);
    expect(await templatesNamed(REPORT_NAME)).toHaveLength(1);

    // A copy of the default template that exists is another template, under a free name, and not the default: the type keeps its own
    const copied = await runImport(zip, [{ type: 'fintelTemplates', items: [report.standard_id], item_modes: [{ key: report.standard_id, mode: 'COPY' }] }], false);
    expect(copied.map(({ status, reason }) => [status, reason])).toEqual([['CREATED', `Added as "${REPORT_NAME} (1)"`]]);
    const copy = await loadTemplate(`${REPORT_NAME} (1)`);
    expect(copy.standard_id).not.toBe(report.standard_id);
    expect(copy.default).toBe(false);
    expect(markingValueOf(copy)).toBe(green.id);
    expect(await defaultsOf('Report')).toEqual([REPORT_NAME]);
  });
});

describe('Fintel templates: an overwrite brings a template changed locally back to the bundle', () => {
  const BUNDLE_NAME = `${PREFIX} overwritten`;
  const OTHER_DEFAULT_NAME = `${PREFIX} other default`;
  const UNPUBLISHED_NAME = `${PREFIX} unpublished`;
  let green: { id: string; standard_id: string };
  let givenReport: { id: string; standard_id: string };
  const loadByStandardId = async (standardId: string) => (await allTemplates()).find((template) => template.standard_id === standardId)!;
  const variableNamesOf = (template: BasicStoreEntityFintelTemplate) => template.fintel_template_widgets.map(({ variable_name }) => variable_name);

  beforeAll(async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
    green = await internalLoadById<BasicStoreEntityMarkingDefinition>(testContext, ADMIN_USER, MARKING_TLP_GREEN);
    [givenReport] = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_CONTAINER_REPORT], { first: 1 });
  });

  afterAll(async () => {
    await deleteTestTemplates();
    vi.restoreAllMocks();
  });

  afterEach(async () => {
    await queryAsAdmin({ query: gql`mutation FintelTemplateOverwriteClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('writes back the name, the published state, the whole list of widgets and the default of its entity type, taken back from another template', async () => {
    await addFintelTemplate(testContext, ADMIN_USER, {
      name: BUNDLE_NAME,
      settings_types: ['Report'],
      start_date: '2026-01-02T00:00:00.000Z',
      default: true,
      fintel_template_widgets: [markedWidget(green.id)],
    }, true);
    await addFintelTemplate(testContext, ADMIN_USER, { name: OTHER_DEFAULT_NAME, settings_types: ['Report'], default: false }, true);
    const template = await loadTemplate(BUNDLE_NAME);
    const otherDefault = await loadTemplate(OTHER_DEFAULT_NAME);
    const { bundle } = await exportBundle([{ type: 'fintelTemplates', items: [template.standard_id] }]);

    // Changed locally: renamed, unpublished, other widgets, and another template made the default of the reports
    await fintelTemplateEditField(testContext, ADMIN_USER, template.id, [
      { key: 'name', value: [`${PREFIX} renamed locally`] },
      { key: 'start_date', value: [null] },
      { key: 'fintel_template_widgets', value: [reportAttributesWidget(givenReport.id)] },
    ]);
    await fintelTemplateEditField(testContext, ADMIN_USER, otherDefault.id, [{ key: 'default', value: [true] }]);
    const changed = await loadByStandardId(template.standard_id);
    expect(changed).toMatchObject({ name: `${PREFIX} renamed locally`, default: false });
    expect(changed.start_date ?? null).toBeNull();
    expect(variableNamesOf(changed)).toEqual(['givenReport']);
    expect(await defaultsOf('Report')).toEqual([OTHER_DEFAULT_NAME]);

    const results = await runImport(bundle, [{ type: 'fintelTemplates' }], false);
    expect(results.map(({ status }) => status)).toEqual(['OVERWRITTEN']);
    const restored = await loadByStandardId(template.standard_id);
    expect(restored.id).toBe(template.id);
    expect(restored).toMatchObject({ name: BUNDLE_NAME, default: true });
    expect(new Date(restored.start_date).toISOString()).toBe('2026-01-02T00:00:00.000Z');
    // The list of widgets is the one of the bundle as a whole, its filter pointing to the marking by its id on this platform
    expect(variableNamesOf(restored)).toEqual(['greenReports']);
    expect(markingValueOf(restored)).toBe(green.id);
    // The default of the reports is the template of the bundle, and only it: the other one lost it
    expect(await defaultsOf('Report')).toEqual([BUNDLE_NAME]);
    expect((await loadByStandardId(otherDefault.standard_id)).default).toBe(false);

    // Back to the state of the bundle: nothing more to write
    const again = await runImport(bundle, [{ type: 'fintelTemplates' }], false);
    expect(again.map(({ status, code }) => `${status}:${code}`)).toEqual(['SKIPPED:unchanged']);
  });

  it('unpublishes a template published locally when the bundle has it not published', async () => {
    await addFintelTemplate(testContext, ADMIN_USER, { name: UNPUBLISHED_NAME, settings_types: ['Grouping'], default: false }, true);
    const template = await loadTemplate(UNPUBLISHED_NAME);
    const { bundle } = await exportBundle([{ type: 'fintelTemplates', items: [template.standard_id] }]);
    await fintelTemplateEditField(testContext, ADMIN_USER, template.id, [{ key: 'start_date', value: ['2026-03-01T00:00:00.000Z'] }]);
    expect((await loadByStandardId(template.standard_id)).start_date).toBeTruthy();

    const results = await runImport(bundle, [{ type: 'fintelTemplates' }], false);
    expect(results.map(({ status }) => status)).toEqual(['OVERWRITTEN']);
    expect((await loadByStandardId(template.standard_id)).start_date ?? null).toBeNull();
  });
});

describe('Fintel templates: a template with the built-in widgets of the platform', () => {
  const BUILT_IN_NAME = `${PREFIX} built-in widgets`;

  beforeAll(() => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
  });

  afterAll(async () => {
    await deleteTestTemplates();
    await queryAsAdmin({ query: gql`mutation FintelTemplateBuiltInClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
    vi.restoreAllMocks();
  });

  it('says a template the platform created with its built-in widgets is up to date when its own export is imported back', async () => {
    // As the UI creates it: with the built-in widgets, some without filters, some with filters on the instance the template is applied to
    await addFintelTemplate(testContext, ADMIN_USER, { name: BUILT_IN_NAME, settings_types: ['Report'], default: false });
    const template = await loadTemplate(BUILT_IN_NAME);
    expect(template.fintel_template_widgets.length).toBeGreaterThan(1);
    const { bundle } = await exportBundle([{ type: 'fintelTemplates', items: [template.standard_id] }]);
    const results = await runImport(bundle, [{ type: 'fintelTemplates' }], false);
    expect(results.map(({ status, code }) => `${status}:${code}`)).toEqual(['SKIPPED:unchanged']);
  });
});

describe('Fintel templates: partial import from the page of an entity type', () => {
  const REPORT_ID = 'finteltemplate--11111111-2222-5333-8444-555555555551';
  const GROUPING_ID = 'finteltemplate--11111111-2222-5333-8444-555555555552';
  const PARTIAL_REPORT = `${PREFIX} partial report`;
  const templateFile = (id: string, configuration: Record<string, unknown>) => [
    `customization/fintel_templates/${id}.json`,
    itemFile('customization.fintelTemplates', id, { standard_id: id, ...configuration }),
  ] as const;
  const zipUpload = async () => createUploadFromBuffer(await buildZip(Object.fromEntries([
    ['metadata.json', metadataFile()],
    ['dependencies.json', '{}'],
    templateFile(REPORT_ID, { name: PARTIAL_REPORT, settings_types: ['Report'], default: true }),
    templateFile(GROUPING_ID, { name: `${PREFIX} partial grouping`, settings_types: ['Grouping'] }),
  ])), 'bundle.zip');
  const preview = async (scope?: string) => queryAsAdmin({ query: PARTIAL_PREVIEW_MUTATION, variables: { file: await zipUpload(), type: 'fintelTemplates', scope } });
  const partialImport = async (items: string[], scope?: string) => {
    return queryAsAdmin({ query: PARTIAL_IMPORT_MUTATION, variables: { file: await zipUpload(), type: 'fintelTemplates', items, scope } });
  };

  beforeAll(() => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
  });

  afterAll(async () => {
    await deleteTestTemplates();
    vi.restoreAllMocks();
  });

  it('previews every template of the bundle without a scope, and only the ones of the entity type with it', async () => {
    const all = await preview();
    expect(all.errors).toBeUndefined();
    expect(all.data?.configPresetPartialImportPreview.type.items.map(({ key }: { key: string }) => key)).toEqual([REPORT_ID, GROUPING_ID]);
    const reports = await preview('Report');
    expect(reports.data?.configPresetPartialImportPreview).toMatchObject({
      default_mode: 'COPY',
      type: { key: 'fintelTemplates', items: [{ key: REPORT_ID, label: `${PARTIAL_REPORT} (Report)`, exists: false, conflict: false, isDefault: true }] },
    });
  });

  it('imports the selected template of the entity type under its standard id, and refuses the id of a template of another type', async () => {
    const { errors: outOfScope } = await partialImport([GROUPING_ID], 'Report');
    expect(outOfScope?.[0]?.message).toBe('Unknown configuration preset item');
    const { data, errors } = await partialImport([REPORT_ID], 'Report');
    expect(errors).toBeUndefined();
    expect(data?.configPresetPartialImport.results).toEqual([{ type: 'fintelTemplates', key: REPORT_ID, status: 'CREATED', reason: null, label: `${PARTIAL_REPORT} (Report)` }]);
    expect(await loadTemplate(PARTIAL_REPORT)).toMatchObject({ standard_id: REPORT_ID, settings_types: ['Report'] });
    expect(await templatesNamed(`${PREFIX} partial grouping`)).toHaveLength(0);
  });

  it('adds a copy of a template that already exists by default, as a partial import adds to the platform', async () => {
    const reports = await preview('Report');
    expect(reports.data?.configPresetPartialImportPreview.type.items).toEqual([expect.objectContaining({ key: REPORT_ID, exists: true, conflict: true })]);
    const { data } = await partialImport([REPORT_ID], 'Report');
    expect(data?.configPresetPartialImport.results).toEqual([expect.objectContaining({ status: 'CREATED', reason: `Added as "${PARTIAL_REPORT} (1)"` })]);
    expect(await loadTemplate(`${PARTIAL_REPORT} (1)`)).toMatchObject({ default: false });
  });
});
