import { useState } from 'react';
import type { FieldSelectedSections } from '@mui/x-date-pickers/models';

/**
 * Section selection of a date field, to spread on a picker, given the picker's value.
 *
 * In a picker with a controlled value, once every section of an empty field is selected (Ctrl+A,
 * or Ctrl+A then Backspace to empty it), x-date-pickers 9 applies the typed keys to the first
 * section: a date typed in one go fills the year only, and typing it again can leave a valid but
 * different date (#19228, mui/mui-x#19997). Selecting the first section instead types the date
 * section by section, as after a click on the field.
 *
 * A field holding a valid date keeps selecting every section, which types correctly and lets
 * Backspace clear the whole field.
 */
const useFieldSectionSelection = (value: unknown) => {
  const [selectedSections, setSelectedSections] = useState<FieldSelectedSections>(null);
  const hasValue = value instanceof Date && !Number.isNaN(value.getTime());
  const onSelectedSectionsChange = (newSelectedSections: FieldSelectedSections) => {
    setSelectedSections(newSelectedSections === 'all' && !hasValue ? 0 : newSelectedSections);
  };
  return { selectedSections, onSelectedSectionsChange };
};

export default useFieldSectionSelection;
