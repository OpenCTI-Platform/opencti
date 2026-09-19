import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
import { screen } from '@testing-library/react';
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
});
