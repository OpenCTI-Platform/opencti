import { describe, expect, it } from 'vitest';
import { buildNotifierUiSchema, variableHelperTemplates, variableHelperWidgets } from './NotifierUtils';

// The Platform mailer connector ui schema, as the backend declares it
const PLATFORM_MAILER_UI_SCHEMA = JSON.stringify({
  title: { 'ui:FieldTemplate': 'TitleVariableHelper', 'ui:widget': 'TitleVariableInput' },
  template: { 'ui:FieldTemplate': 'TemplateVariableHelper', 'ui:widget': 'textarea' },
});

describe('buildNotifierUiSchema', () => {
  it('keeps the connector ui schema and adds the shared options', () => {
    const schema = buildNotifierUiSchema(PLATFORM_MAILER_UI_SCHEMA);
    expect(schema.title).toEqual({ 'ui:FieldTemplate': 'TitleVariableHelper', 'ui:widget': 'TitleVariableInput' });
    expect(schema.template).toEqual({ 'ui:FieldTemplate': 'TemplateVariableHelper', 'ui:widget': 'textarea' });
    expect(schema['ui:options']).toMatchObject({ orderable: false });
  });

  it('builds the shared options alone without a connector ui schema', () => {
    const schema = buildNotifierUiSchema(undefined);
    expect(schema.title).toBeUndefined();
    expect(schema['ui:options']).toMatchObject({ orderable: false });
  });
});

describe('variable helpers', () => {
  it('registers the field templates and the widget the Platform mailer names on its fields', () => {
    const { title, template } = JSON.parse(PLATFORM_MAILER_UI_SCHEMA);
    expect(variableHelperTemplates).toHaveProperty(title['ui:FieldTemplate']);
    expect(variableHelperTemplates).toHaveProperty(template['ui:FieldTemplate']);
    expect(variableHelperWidgets).toHaveProperty(title['ui:widget']);
  });
});
