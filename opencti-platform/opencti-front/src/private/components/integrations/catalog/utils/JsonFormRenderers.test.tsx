import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { JsonForms } from '@jsonforms/react';
import { materialRenderers } from '@jsonforms/material-renderers';
import testRender from '../../../../../utils/tests/test-render';
import JsonFormArrayRenderer, { jsonFormArrayTester } from './JsonFormArrayRenderer';
import JsonFormInputRenderer, { jsonFormInputTester } from './JsonFormInputRenderer';
import JsonFormEnumRenderer, { jsonFormEnumTester } from './JsonFormEnumRenderer';
import JsonFormBooleanRenderer, { jsonFormBooleanTester } from './JsonFormBooleanRenderer';
import { JsonFormPasswordRenderer, jsonFormPasswordTester } from './JsonFormPasswordRenderer';

const renderers = [
  ...materialRenderers,
  { tester: jsonFormPasswordTester, renderer: JsonFormPasswordRenderer },
  { tester: jsonFormArrayTester, renderer: JsonFormArrayRenderer },
  { tester: jsonFormInputTester, renderer: JsonFormInputRenderer },
  { tester: jsonFormEnumTester, renderer: JsonFormEnumRenderer },
  { tester: jsonFormBooleanTester, renderer: JsonFormBooleanRenderer },
];

// The AbuseIPDB contract, trimmed to one field per type the drawer can show.
const schema = {
  type: 'object',
  properties: {
    CONNECTOR_NAME: { type: 'string', description: 'Connector name' },
    ABUSEIPDB_LIMIT: { type: 'integer', description: 'AbuseIPDB limit' },
    CONNECTOR_LOG_LEVEL: { type: 'string', enum: ['error', 'info', 'debug'], description: 'Connector log level' },
    ABUSEIPDB_CREATE_INDICATOR: { type: 'boolean', description: 'AbuseIPDB create indicator' },
    CONNECTOR_SCOPE: { type: 'array', items: { type: 'string' }, default: [], description: 'The scope of the connector.' },
  },
};

const uischema = {
  type: 'VerticalLayout',
  elements: Object.keys(schema.properties).map((key) => ({ type: 'Control', scope: `#/properties/${key}` })),
};

// An array option whose items are restricted to an enum, from the Google DTM contract, and a free one.
const arraySchema = {
  type: 'object',
  properties: {
    GOOGLE_DTM_ALERT_TYPE: { type: 'array', default: [], items: { type: 'string', enum: ['Document', 'Email', 'Forum Post'] } },
    CONNECTOR_SCOPE: { type: 'array', default: [], items: { type: 'string' } },
  },
};

const renderArrayField = (key: keyof typeof arraySchema.properties, data: Record<string, string[]> = {}) => {
  let lastData: Record<string, unknown> = data;
  const result = testRender(
    <JsonForms
      schema={arraySchema}
      uischema={{ type: 'Control', scope: `#/properties/${key}` }}
      data={data}
      renderers={renderers}
      onChange={({ data: next }) => {
        lastData = next;
      }}
    />,
  );
  return { ...result, getData: () => lastData };
};

describe('the connector configuration renderers', () => {
  beforeAll(() => {
    // Radix primitives observe their trigger; jsdom ships no ResizeObserver and
    // the tree comes back empty without it.
    if (!('ResizeObserver' in window)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).ResizeObserver = class {
        observe() {}

        unobserve() {}

        disconnect() {}
      };
    }
  });

  it('renders every control with a library component, never a MUI one', () => {
    const { container } = testRender(
      <JsonForms
        schema={schema}
        uischema={uischema}
        data={{ CONNECTOR_SCOPE: ['abuseipdb-blacklist'] }}
        renderers={renderers}
        onChange={() => {}}
      />,
    );

    // Text and number both land on the library Input, the enum on the library
    // Select, the boolean on the library Checkbox.
    const labels = [...container.querySelectorAll('label')].map((l) => l.textContent?.trim());
    expect(labels).toEqual(expect.arrayContaining(['CONNECTOR NAME', 'ABUSEIPDB LIMIT', 'ABUSEIPDB CREATE INDICATOR', 'CONNECTOR SCOPE']));
    expect(container.querySelector('input[type="number"]')).not.toBeNull();
    expect(screen.getAllByRole('combobox').length).toBe(2); // the enum trigger + the array input
    expect(screen.getByRole('checkbox')).toBeInTheDocument();

    expect(container.querySelectorAll('.MuiInputBase-root, .MuiSelect-select, .MuiCheckbox-root')).toHaveLength(0);
  });

  it('puts an array field description below the control, not above it', () => {
    const { container } = testRender(
      <JsonForms
        schema={schema}
        uischema={uischema}
        data={{ CONNECTOR_SCOPE: ['abuseipdb-blacklist'] }}
        renderers={renderers}
        onChange={() => {}}
      />,
    );

    const description = screen.getByText('The scope of the connector.');
    const field = container.querySelector('[data-combobox-field]');
    expect(field).not.toBeNull();
    // DOCUMENT_POSITION_FOLLOWING: the description comes after the field.
    expect(field!.compareDocumentPosition(description) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('offers the enum values of an array option and lets several of them be picked', async () => {
    const { user, getData } = renderArrayField('GOOGLE_DTM_ALERT_TYPE');

    await user.click(screen.getByRole('combobox'));
    const options = await screen.findAllByRole('option');
    expect(options.map((option) => option.textContent)).toEqual(['Document', 'Email', 'Forum Post']);

    await user.click(screen.getByRole('option', { name: 'Document' }));
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByRole('option', { name: 'Forum Post' }));
    // JsonForms reports the data after the render
    await waitFor(() => expect(getData().GOOGLE_DTM_ALERT_TYPE).toEqual(['Document', 'Forum Post']));
  });

  it('does not add a value outside the enum of an array option', async () => {
    const { user, getData } = renderArrayField('GOOGLE_DTM_ALERT_TYPE');

    await user.type(screen.getByRole('combobox'), 'Foo{Enter}');
    expect(screen.queryByText('Foo')).not.toBeInTheDocument();
    await waitFor(() => expect(getData().GOOGLE_DTM_ALERT_TYPE ?? []).toEqual([]));
  });

  it('keeps showing a stored value outside the enum, so it can be removed', () => {
    renderArrayField('GOOGLE_DTM_ALERT_TYPE', { GOOGLE_DTM_ALERT_TYPE: ['Foo'] });

    expect(screen.getByText('Foo')).toBeInTheDocument();
  });

  it('still adds a typed value to an array option without enum', async () => {
    const { user, getData } = renderArrayField('CONNECTOR_SCOPE');

    await user.type(screen.getByRole('combobox'), 'indicator{Enter}');
    await waitFor(() => expect(getData().CONNECTOR_SCOPE).toEqual(['indicator']));
  });
});
