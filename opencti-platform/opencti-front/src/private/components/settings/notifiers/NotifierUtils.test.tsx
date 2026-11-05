import { describe, expect, it } from 'vitest';
import { buildNotifierUiSchema, notifierFormTemplates } from './NotifierUtils';

// The title entry of the Platform mailer connector ui schema, as the backend declares it
const PLATFORM_MAILER_UI_SCHEMA = JSON.stringify({
  title: { 'ui:FieldTemplate': 'NotifierVariablesHelpFieldTemplate' },
  template: { 'ui:widget': 'textarea' },
});

describe('buildNotifierUiSchema', () => {
  it('keeps the connector ui schema and adds the shared options', () => {
    const schema = buildNotifierUiSchema(PLATFORM_MAILER_UI_SCHEMA);
    expect(schema.template).toEqual({ 'ui:widget': 'textarea' });
    expect(schema.title).toEqual({ 'ui:FieldTemplate': 'NotifierVariablesHelpFieldTemplate' });
    expect(schema['ui:options']).toMatchObject({ orderable: false });
  });

  it('builds the shared options alone without a connector ui schema', () => {
    const schema = buildNotifierUiSchema(undefined);
    expect(schema.title).toBeUndefined();
    expect(schema['ui:options']).toMatchObject({ orderable: false });
  });
});

describe('notifierFormTemplates', () => {
  it('registers the template the Platform mailer names on its title', () => {
    const templateName = JSON.parse(PLATFORM_MAILER_UI_SCHEMA).title['ui:FieldTemplate'];
    expect(notifierFormTemplates).toHaveProperty(templateName);
  });
});
