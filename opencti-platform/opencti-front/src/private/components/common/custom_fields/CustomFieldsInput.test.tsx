import { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { CustomFieldInput } from './CustomFieldsInput';
import type { CustomFieldDef, CustomFieldValue } from '../../../../utils/customFields';

vi.mock('../../../../components/i18n', () => ({ useFormatter: () => ({ t_i18n: (key: string) => key }) }));
vi.mock('../../../../components/common/input/DateTimePicker', () => ({ default: () => null }));
vi.mock('../../../../components/fields/markdownField/MarkdownFieldBase', () => ({ default: () => null }));

const definition = (field_type: string): CustomFieldDef => ({
  id: 'custom-field',
  name: 'custom_field',
  label: 'Custom field',
  field_type,
  min_value: 0,
  max_value: 10,
  select_options: ['First', 'Second'],
  entity_type_settings: [],
});

const ControlledField = ({ type, initialValue, onSubmit }: {
  type: string;
  initialValue: CustomFieldValue;
  onSubmit: (value: CustomFieldValue) => void;
}) => {
  const [value, setValue] = useState(initialValue);
  return <CustomFieldInput definition={definition(type)} mandatory={false} value={value} onChange={setValue} onSubmit={onSubmit} />;
};

describe('CustomFieldInput design-system controls', () => {
  it('submits text changes on blur and Enter, but not unchanged values', () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn();
    render(<CustomFieldInput definition={definition('string')} mandatory={false} value="initial" onChange={onChange} onSubmit={onSubmit} />);
    const input = screen.getByRole('textbox', { name: 'Custom field' });
    expect(input.className).not.toContain('MuiInputBase-input');
    fireEvent.blur(input);
    expect(onSubmit).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: 'edited' } });
    expect(onChange).toHaveBeenLastCalledWith('edited');
    expect(onSubmit).not.toHaveBeenCalled();
    fireEvent.blur(input);
    expect(onSubmit).toHaveBeenLastCalledWith('edited');
    fireEvent.change(input, { target: { value: 'entered' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSubmit).toHaveBeenLastCalledWith('entered');
  });

  it('refreshes the local text draft when stored values change', () => {
    const props = { definition: definition('string'), mandatory: false };
    const { rerender } = render(<CustomFieldInput {...props} value="initial" />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'draft' } });
    rerender(<CustomFieldInput {...props} value="refreshed" />);
    expect(screen.getByRole('textbox')).toHaveValue('refreshed');
  });

  it('preserves integer bounds and submits numbers as string drafts', () => {
    const onSubmit = vi.fn();
    render(<CustomFieldInput definition={definition('integer')} mandatory={false} value="0" onSubmit={onSubmit} />);
    const input = screen.getByRole('spinbutton', { name: 'Custom field' });
    expect(input).toHaveAttribute('min', '0');
    expect(input).toHaveAttribute('max', '10');
    fireEvent.change(input, { target: { value: '5' } });
    fireEvent.blur(input);
    expect(onSubmit).toHaveBeenCalledWith('5');
  });

  it('allows false for a mandatory boolean and submits switch changes', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const onSubmit = vi.fn();
    const props = { definition: definition('boolean'), mandatory: true, onChange, onSubmit };
    const { rerender } = render(<CustomFieldInput {...props} value={false} />);
    const input = screen.getByRole('switch', { name: 'Custom field *' });
    expect(input).not.toBeChecked();
    expect(input).not.toBeRequired();
    await user.click(input);
    expect(onChange).toHaveBeenLastCalledWith(true);
    expect(onSubmit).toHaveBeenLastCalledWith(true);
    rerender(<CustomFieldInput {...props} value={true} />);
    await user.click(input);
    expect(onSubmit).toHaveBeenLastCalledWith(false);
  });

  it('submits single selections and clears them through None', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(<ControlledField type="select" initialValue="" onSubmit={onSubmit} />);
    await user.click(screen.getByRole('combobox'));
    await user.click(screen.getByRole('option', { name: 'First' }));
    expect(onSubmit).toHaveBeenLastCalledWith('First');
    await user.click(screen.getByRole('combobox'));
    await user.click(screen.getByRole('option', { name: 'None' }));
    expect(onSubmit).toHaveBeenLastCalledWith('');
  });

  it('preserves multiple selections, selects by keyboard, and clears all values', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(<ControlledField type="multi_select" initialValue={['First']} onSubmit={onSubmit} />);
    const input = screen.getByRole('combobox');
    await user.type(input, 'Second');
    await user.keyboard('{ArrowDown}{Enter}');
    expect(onSubmit).toHaveBeenLastCalledWith(['First', 'Second']);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear' }));
    expect(onSubmit).toHaveBeenLastCalledWith([]);
  });

  it('does not submit arbitrary search text as a multi-select value', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(<ControlledField type="multi_select" initialValue={[]} onSubmit={onSubmit} />);
    await user.type(screen.getByRole('combobox'), 'Not an option');
    await user.keyboard('{Enter}{Tab}');
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
