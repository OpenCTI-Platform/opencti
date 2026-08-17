import { beforeEach, describe, expect, it, vi } from 'vitest';
import { addFintelTemplate, checkFintelTemplateWidgetsValidity, fintelTemplateExport } from '../../../src/modules/fintelTemplate/fintelTemplate-domain';
import { type FintelTemplateWidget, WidgetPerspective } from '../../../src/generated/graphql';
import * as middleware from '../../../src/database/middleware';
import * as ee from '../../../src/enterprise-edition/ee';
import * as redis from '../../../src/database/redis';
import * as userActionListener from '../../../src/listener/UserActionListener';
import * as workspaceUtils from '../../../src/modules/workspace/workspace-utils';
import { convertFintelTemplateToStix } from '../../../src/modules/fintelTemplate/fintelTemplate-converter';
import { FINTEL_TEMPLATE_DEFINITION } from '../../../src/modules/fintelTemplate/fintelTemplate';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

vi.mock('../../../src/database/stix-2-1-converter', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/stix-2-1-converter')>();
  return {
    ...actual,
    buildStixObject: vi.fn(() => ({
      id: 'fintel-template--1',
      type: 'fintel-template',
      spec_version: '2.1',
      created: '2025-01-01T00:00:00.000Z',
      modified: '2025-01-01T00:00:00.000Z',
      extensions: { 'extension-definition--test': { foo: 'bar' } },
    })),
  };
});

describe('fintel template domain utils', () => {
  it('should check fintel template widgets variable names validity', async () => {
    // -- list widgets --
    // no error
    let fintelTemplateWidgets: FintelTemplateWidget[] = [{
      variable_name: 'List1',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    checkFintelTemplateWidgetsValidity(fintelTemplateWidgets); // no expect, it should work
    // should have a variable_name with no space
    fintelTemplateWidgets = [{
      variable_name: 'My list',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');

    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: '$list',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // -- attribute widgets --
    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
          ],
        }],
        type: 'attribute',
      },
    }];
    checkFintelTemplateWidgetsValidity(fintelTemplateWidgets); // no expect, it should work
    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute&Widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // all the columns should have a variable name
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Attributes should all have a variable name');
    // the columns should have a variable name with no space
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date', variableName: 'Publication date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // the columns should have a variable name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date', variableName: 'Publication/date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
  });
});

describe('fintel template page option defaults', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should persist true defaults when creating a template without explicit values', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
    const createEntitySpy = vi.spyOn(middleware, 'createEntity').mockResolvedValue({ id: 'template--1', name: 'Template 1' } as never);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue([]);
    vi.spyOn(redis, 'notify').mockImplementation((_, data) => Promise.resolve(data));

    await addFintelTemplate(testContext, ADMIN_USER, {
      name: 'Template 1',
      description: 'Template description',
      settings_types: ['Report'],
      instance_filters: '',
      template_content: '',
      start_date: '2025-01-01T00:00:00.000Z',
      fintel_template_widgets: [],
    }, true);

    const inputSent = createEntitySpy.mock.calls[0][2] as Record<string, boolean>;
    expect(inputSent.default).toEqual(false);
    expect(inputSent.includeCoverPageByDefault).toEqual(true);
    expect(inputSent.includeBackPageByDefault).toEqual(true);
  });

  it('should export true defaults when values are absent', async () => {
    vi.spyOn(workspaceUtils, 'convertWidgetsIds').mockResolvedValue(undefined);
    const exported = await fintelTemplateExport(testContext, ADMIN_USER, {
      name: 'Template 1',
      description: 'Template description',
      settings_types: ['Report'],
      instance_filters: '',
      template_content: '',
      start_date: '2025-01-01T00:00:00.000Z',
      fintel_template_widgets: [],
      default: false,
    } as never);

    const parsed = JSON.parse(exported);
    expect(parsed.configuration.includeCoverPageByDefault).toEqual(true);
    expect(parsed.configuration.includeBackPageByDefault).toEqual(true);
  });

  it('should preserve explicit false defaults in export', async () => {
    vi.spyOn(workspaceUtils, 'convertWidgetsIds').mockResolvedValue(undefined);
    const exported = await fintelTemplateExport(testContext, ADMIN_USER, {
      name: 'Template 1',
      description: 'Template description',
      settings_types: ['Report'],
      instance_filters: '',
      template_content: '',
      start_date: '2025-01-01T00:00:00.000Z',
      fintel_template_widgets: [],
      default: false,
      includeCoverPageByDefault: false,
      includeBackPageByDefault: false,
    } as never);

    const parsed = JSON.parse(exported);
    expect(parsed.configuration.includeCoverPageByDefault).toEqual(false);
    expect(parsed.configuration.includeBackPageByDefault).toEqual(false);
  });

  it('should fallback converter values to true', () => {
    const stix = convertFintelTemplateToStix({
      name: 'Template 1',
      description: 'Template description',
      settings_types: ['Report'],
      instance_filters: '',
      template_content: '',
      fintel_template_widgets: [],
      start_date: '2025-01-01T00:00:00.000Z',
    } as never);

    expect(stix.includeCoverPageByDefault).toEqual(true);
    expect(stix.includeBackPageByDefault).toEqual(true);
  });

  it('should keep explicit false converter values', () => {
    const stix = convertFintelTemplateToStix({
      name: 'Template 1',
      description: 'Template description',
      settings_types: ['Report'],
      instance_filters: '',
      template_content: '',
      fintel_template_widgets: [],
      start_date: '2025-01-01T00:00:00.000Z',
      includeCoverPageByDefault: false,
      includeBackPageByDefault: false,
    } as never);

    expect(stix.includeCoverPageByDefault).toEqual(false);
    expect(stix.includeBackPageByDefault).toEqual(false);
  });

  it('should expose page default attributes in module definition', () => {
    const attributeNames = FINTEL_TEMPLATE_DEFINITION.attributes.map((attribute) => attribute.name);
    expect(attributeNames).toContain('includeCoverPageByDefault');
    expect(attributeNames).toContain('includeBackPageByDefault');
  });
});
