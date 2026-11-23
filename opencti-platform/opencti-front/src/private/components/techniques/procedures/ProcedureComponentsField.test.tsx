import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ProcedureComponentsField, { ComponentRow, componentRowErrors } from './ProcedureComponentsField';

const row = (id: string, type: ComponentRow['type'], value = id): ComponentRow => ({ id, entity_type: 'Text', observable_value: value, type });

const WBADMIN: ComponentRow[] = [
  { id: 'wbadmin', entity_type: 'Process', observable_value: 'wbadmin.exe', type: 'primary' },
  row('start', 'primary', 'start backup'),
  row('quiet', 'secondary', '-quiet'),
];

const renderField = (rows: ComponentRow[], overrides: Partial<React.ComponentProps<typeof ProcedureComponentsField>> = {}) => {
  const onChange = vi.fn();
  const search = vi.fn().mockResolvedValue([]);
  const createText = vi.fn();
  testRender(<ProcedureComponentsField rows={rows} onChange={onChange} search={search} createText={createText} {...overrides} />);
  return { onChange, search, createText };
};

describe('componentRowErrors', () => {
  it('accepts a sequence that starts with a primary component', () => {
    expect(componentRowErrors(WBADMIN)).toEqual([null, null, null]);
  });

  it('flags a secondary first component and a repeated observable', () => {
    expect(componentRowErrors([row('a', 'secondary'), row('b', 'primary'), row('a', 'secondary')])).toEqual([
      'The first component must be Primary.',
      null,
      'This observable is already in the sequence.',
    ]);
  });
});

describe('ProcedureComponentsField', () => {
  it('names the field Components', () => {
    renderField(WBADMIN);
    expect(screen.getByText('Components')).toBeDefined();
  });

  it('moves a component up', () => {
    const { onChange } = renderField(WBADMIN);
    fireEvent.click(screen.getByRole('button', { name: 'Move component 1 up' }));
    expect(onChange).toHaveBeenCalledWith([WBADMIN[1], WBADMIN[0], WBADMIN[2]]);
  });

  it('removes a component', () => {
    const { onChange } = renderField(WBADMIN);
    fireEvent.click(screen.getByRole('button', { name: 'Remove component 2' }));
    expect(onChange).toHaveBeenCalledWith([WBADMIN[0], WBADMIN[1]]);
  });

  it('shows the error of a secondary first component', () => {
    renderField([row('a', 'secondary'), row('b', 'primary')]);
    expect(screen.getByText('The first component must be Primary.')).toBeDefined();
  });

  it('creates a Text observable from a typed value and appends it as secondary', async () => {
    const createText = vi.fn().mockResolvedValue({ id: 'new', entity_type: 'Text', observable_value: '-include:ntds.dit' });
    const { onChange } = renderField(WBADMIN, { createText });
    const input = screen.getByRole('combobox', { name: 'Add a component' });
    fireEvent.change(input, { target: { value: '-include:ntds.dit' } });
    fireEvent.click(await screen.findByText(/Create Text observable/));
    await waitFor(() => expect(createText).toHaveBeenCalledWith('-include:ntds.dit'));
    await waitFor(() => expect(onChange).toHaveBeenCalledWith([...WBADMIN, { id: 'new', entity_type: 'Text', observable_value: '-include:ntds.dit', type: 'secondary' }]));
  });
});
