import React, { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { enUS } from 'date-fns/locale';
import BaseDatePicker from './BaseDatePicker';

// An onKeyDown on the text field replaces the field's own one, as in FilterDate.
const ControlledDatePicker = ({ textFieldOnKeyDown }: { textFieldOnKeyDown?: React.KeyboardEventHandler }) => {
  const [value, setValue] = useState<Date | null>(null);
  return (
    <LocalizationProvider dateAdapter={AdapterDateFns} adapterLocale={enUS}>
      <BaseDatePicker
        label="Date"
        value={value}
        onChange={setValue}
        slotProps={textFieldOnKeyDown ? { textField: () => ({ onKeyDown: textFieldOnKeyDown }) } : undefined}
      />
    </LocalizationProvider>
  );
};

// The sections, MM/DD/YYYY. While every one is selected, they are edited as one element and
// lose their spinbutton role, so they are reached through the DOM.
const renderPicker = (textFieldOnKeyDown?: React.KeyboardEventHandler) => {
  const rendered = render(<ControlledDatePicker textFieldOnKeyDown={textFieldOnKeyDown} />);
  const field = screen.getByRole('group', { name: 'Date' });
  const sectionList = field.querySelector('.MuiPickersSectionList-root') as HTMLElement;
  const section = (index: number) => sectionList.querySelectorAll<HTMLElement>('.MuiPickersSectionList-sectionContent')[index];
  const isEverySectionSelected = () => sectionList.getAttribute('contenteditable') === 'true';
  return { ...rendered, sectionList, section, isEverySectionSelected };
};

describe('BaseDatePicker', () => {
  it('selects the first section when every section of the empty field is selected', async () => {
    const user = userEvent.setup();
    const { section, isEverySectionSelected } = renderPicker();
    await user.click(section(1));
    await user.keyboard('{Control>}a{/Control}');
    expect(isEverySectionSelected()).toBe(false);
    expect(document.activeElement).toBe(section(0));
  });

  it('keeps every section of a partly typed date selected', async () => {
    const user = userEvent.setup();
    const { sectionList, section, isEverySectionSelected } = renderPicker();
    await user.click(section(0));
    await user.keyboard('12');
    expect(sectionList).toHaveTextContent('12/DD/YYYY');
    await user.keyboard('{Control>}a{/Control}');
    expect(isEverySectionSelected()).toBe(true);
  });

  it.each([
    ['', undefined],
    [', with an onKeyDown on the text field', vi.fn()],
  ])('gives back its sections to a partly typed date emptied with Delete%s', async (_, textFieldOnKeyDown) => {
    // The value of a partly typed date is null already: emptying it calls no onChange, and Delete
    // requests no selection.
    const user = userEvent.setup();
    const { sectionList, section, isEverySectionSelected } = renderPicker(textFieldOnKeyDown);
    await user.click(section(0));
    await user.keyboard('12');
    await user.keyboard('{Control>}a{/Control}{Delete}');
    expect(sectionList).toHaveTextContent('MM/DD/YYYY');
    expect(isEverySectionSelected()).toBe(false);
    await user.click(section(1));
    await user.keyboard('16');
    expect(sectionList).toHaveTextContent('MM/16/YYYY');
    if (textFieldOnKeyDown) {
      expect(textFieldOnKeyDown).toHaveBeenCalledWith(expect.objectContaining({ key: 'Delete' }));
    }
  });
});
