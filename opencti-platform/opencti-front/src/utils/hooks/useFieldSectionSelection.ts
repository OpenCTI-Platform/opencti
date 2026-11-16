import { useLayoutEffect, useRef, useState } from 'react';
import type { FieldRef, FieldSelectedSections } from '@mui/x-date-pickers/models';

/**
 * Section selection of a date field, spread on a picker by the wrappers of
 * `components/common/input/picker`, with `fieldRef` handed to the picker's field slot.
 *
 * While every section of an empty field is selected, x-date-pickers 9 edits the field as a whole
 * (mui/mui-x#19997): a date typed in one go fills the first section only, and typing it again can
 * leave a valid but different date (#19228); a click on a section is ignored, so the next key is
 * lost. Selecting the first section instead types the date section by section, as after a click
 * on the field. That covers the field emptied by Ctrl+A then Backspace too: the picker selects
 * every section again while the sections still hold the previous date, so the selection is
 * checked again once the emptied field has rendered.
 *
 * As soon as one section holds something (a date, or a date partly typed, which the picker
 * reports as a null value), every section stays selected, so Backspace clears the whole field.
 */
const useFieldSectionSelection = () => {
  const fieldRef = useRef<FieldRef<Date | null>>(null);
  const [selectedSections, setSelectedSections] = useState<FieldSelectedSections>(null);
  const isEmpty = () => fieldRef.current?.getSections().every((section) => section.value === '') ?? false;
  const onSelectedSectionsChange = (newSelectedSections: FieldSelectedSections) => {
    setSelectedSections(newSelectedSections === 'all' && isEmpty() ? 0 : newSelectedSections);
  };
  useLayoutEffect(() => {
    if (selectedSections === 'all' && isEmpty()) {
      setSelectedSections(0);
    }
  });
  return { fieldRef, selectedSections, onSelectedSectionsChange };
};

export default useFieldSectionSelection;
