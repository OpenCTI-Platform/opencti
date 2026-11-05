import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { buildNotifierUiSchema, NOTIFIER_CONNECTOR_EMAIL_ID, NOTIFIER_TITLE_VARIABLES_DOC, NotifierVariablesHelp } from './NotifierUtils';

const SIMPLE_MAILER_ID = '08f9f00f-4e52-4466-ae27-be9fa9813a88';

describe('NotifierVariablesHelp', () => {
  it('shows a short help, a documentation link and an information icon', () => {
    testRender(<NotifierVariablesHelp />);
    expect(screen.getByText(/Insert notification data with variables in the title or the template\./)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'See the available variables' });
    expect(link).toHaveAttribute('href', NOTIFIER_TITLE_VARIABLES_DOC);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByLabelText('How to insert notification data')).toBeInTheDocument();
  });
});

describe('buildNotifierUiSchema', () => {
  it('puts the variables help above the title of the Platform mailer', () => {
    const schema = buildNotifierUiSchema(null, NOTIFIER_CONNECTOR_EMAIL_ID);
    expect(schema.title['ui:FieldTemplate']).toBeDefined();
    expect(schema.title['ui:help']).toBeUndefined();
  });

  it('adds no help to the other connectors', () => {
    expect(buildNotifierUiSchema(null, SIMPLE_MAILER_ID).title).toBeUndefined();
    expect(buildNotifierUiSchema(null, undefined).title).toBeUndefined();
  });

  it('keeps the connector ui schema and the shared options', () => {
    const schema = buildNotifierUiSchema('{"template":{"ui:widget":"textarea"}}', NOTIFIER_CONNECTOR_EMAIL_ID);
    expect(schema.template).toEqual({ 'ui:widget': 'textarea' });
    expect(schema['ui:options']).toMatchObject({ orderable: false });
    expect(schema.title).toBeDefined();
  });

  it('keeps a title ui entry from the connector ui schema when adding the help', () => {
    const schema = buildNotifierUiSchema('{"title":{"ui:placeholder":"x"}}', NOTIFIER_CONNECTOR_EMAIL_ID);
    expect(schema.title).toMatchObject({ 'ui:placeholder': 'x' });
    expect(schema.title['ui:FieldTemplate']).toBeDefined();
  });
});
