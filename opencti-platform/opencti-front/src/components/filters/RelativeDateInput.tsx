import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import TextField from '@mui/material/TextField';
import MuiIconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import ScheduleOutlined from '@mui/icons-material/ScheduleOutlined';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { CalendarIcon } from '@mui/x-date-pickers/icons';
import { Link } from 'react-router';
import { useFormatter } from '../i18n';
import { isValidDate, RELATIVE_DATE_REGEX } from '../../utils/String';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';

interface RelativeDateInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  label: string;
  valueOrder: number;
  dateInput: string[];
  setDateInput: (value: string[]) => void;
  /** Only ONE field in the popover may claim focus. */
  autoFocus?: boolean;
  /** Shows a relative-date shortcuts icon (reusing QuickRelativeDateFiltersButtons) next to the
   * field, in both native and free-text modes. Only meaningful/passed for the From field. */
  showShortcuts?: boolean;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  label,
  valueOrder,
  dateInput,
  setDateInput,
  autoFocus = false,
  showShortcuts = false,
}) => {
  const { t_i18n, smhd } = useFormatter();
  const [isDatePickerOpen, setIsDatePickerOpen] = useState(false);
  const [shortcutsAnchorEl, setShortcutsAnchorEl] = useState<HTMLElement | null>(null);
  // Local typed-text buffer, decoupled from the `dateInput` prop so that fast typing isn't
  // clobbered by the parent's own re-render cycle (`dateInput`/`setDateInput` is a shared array
  // covering both From/To fields). Re-synced from the prop whenever it changes externally
  // (calendar pick, initial value, or the sibling field's edits).
  const [draft, setDraft] = useState(dateInput[valueOrder]);
  // While the user is actively typing in free-text mode, show the raw value (so they can type/edit
  // a date-math expression like 'now-7d'). While not focused, show a locale-formatted date when
  // the stored value is a real absolute date, same as the other date pickers in the app.
  const [isEditing, setIsEditing] = useState(false);
  // Anchor the free-text mode's calendar/shortcuts popovers to the whole field container (not
  // just the small icon), so they open at the same position as the native mode's own popper
  // (start of the input), keeping the two modes visually consistent.
  const fieldContainerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setDraft(dateInput[valueOrder]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dateInput[valueOrder]]);

  const generateErrorMessage = (values: string[]) => {
    const newValue = values[valueOrder];
    if (!newValue) {
      return t_i18n('The value must not be empty');
    }
    if (values[0] === values[1]) {
      return t_i18n('The values must be different.');
    }
    if (!RELATIVE_DATE_REGEX.test(newValue) && !isValidDate(newValue)) {
      return t_i18n('The value must be a datetime or a relative date expressed in date math. See {link} for more information.', {
        values: {
          link: (
            <Link target="_blank" to="https://docs.opencti.io/latest/reference/filters/?H=filters#operators">
              {t_i18n('our documentation')}
            </Link>
          ),
        },
      });
    }
    return undefined;
  };
  const isValuesIntervalValid = (values: string[]) => {
    const isValidString = values.every((v) => RELATIVE_DATE_REGEX.test(v) || isValidDate(v));
    if (values.length === 2 && values[0] !== values[1] && isValidString) {
      return true;
    }
    return false;
  };
  const handleChangeRangeDateFilter = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
    if (isValuesIntervalValid(newValues)) {
      helpers?.handleReplaceFilterValues(
        filter?.id ?? '',
        newValues,
      );
    }
  };
  const handleChangeValue = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
  };
  const handleChangeAbsoluteDateFilter = (value: Date | null) => {
    if (value) {
      const iso = value.toISOString();
      setDraft(iso);
      handleChangeRangeDateFilter(iso);
    }
    setIsDatePickerOpen(false);
  };

  const errorMessage = generateErrorMessage(dateInput);
  const committedValue = dateInput[valueOrder];

  // Same alternating behavior everywhere (root popover and nested-group row alike): once the
  // committed value is a real absolute date, use the real native MUI field (locale-correct
  // segmented month/day/year, arrow-key navigable, MUI's own standard behavior, built-in
  // calendar affordance). Only free text (needed to type a date-math expression like 'now-7d')
  // falls back to a plain TextField + a calendar icon (MUI's own `CalendarIcon`, same as the
  // native mode's built-in one, for visual consistency) that opens an anchored picker overlay to
  // go back to picking a real date. The only difference for the nested-group row's From field:
  // an extra shortcuts icon (`showShortcuts`), present in both modes.
  const isAbsoluteMode = isValidDate(committedValue);

  const shortcutsButton = showShortcuts && (
    <MuiIconButton
      size="small"
      edge="end"
      onClick={(event) => setShortcutsAnchorEl(event.currentTarget)}
      aria-label="relative date shortcuts"
    >
      <ScheduleOutlined fontSize="small" />
    </MuiIconButton>
  );
  const shortcutsPopover = showShortcuts && (
    <Popover
      open={!!shortcutsAnchorEl}
      anchorEl={shortcutsAnchorEl}
      onClose={() => setShortcutsAnchorEl(null)}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
    >
      <QuickRelativeDateFiltersButtons
        filter={filter}
        helpers={helpers}
        handleClose={() => setShortcutsAnchorEl(null)}
      />
    </Popover>
  );

  if (isAbsoluteMode) {
    return (
      <div style={{ display: 'flex', flex: 1, minWidth: 0, alignItems: 'center' }}>
        <DateTimePicker
          label={label}
          value={new Date(committedValue)}
          onAccept={(value) => {
            if (value) {
              handleChangeRangeDateFilter(value.toISOString());
            }
          }}
          slotProps={{
            textField: {
              id: filter?.id ?? `${filterKey}-id`,
              size: 'small',
              variant: 'outlined',
              fullWidth: true,
              autoFocus,
              error: errorMessage !== undefined,
              helperText: errorMessage,
            },
          }}
        />
        {shortcutsButton}
        {shortcutsPopover}
      </div>
    );
  }

  const displayValue = !isEditing && isValidDate(draft) ? smhd(draft) : draft;

  return (
    <div ref={fieldContainerRef} style={{ display: 'flex', flex: 1, minWidth: 0 }}>
      <TextField
        variant="outlined"
        size="small"
        fullWidth={true}
        id={filter?.id ?? `${filterKey}-id`}
        label={label}
        value={displayValue}
        onChange={(event) => {
          setDraft(event.target.value);
          handleChangeValue(event.target.value);
        }}
        autoFocus={autoFocus}
        onFocus={() => setIsEditing(true)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            handleChangeRangeDateFilter(draft);
          }
        }}
        onBlur={() => {
          handleChangeRangeDateFilter(draft);
          setIsEditing(false);
        }}
        error={errorMessage !== undefined}
        helperText={errorMessage}
        slotProps={{
          input: {
            endAdornment: (
              <MuiIconButton
                size="small"
                edge="end"
                onClick={() => setIsDatePickerOpen(true)}
                aria-label="open date picker"
              >
                <CalendarIcon fontSize="small" />
              </MuiIconButton>
            ),
          },
        }}
      />
      {shortcutsButton}
      {/* The picker's own field is rendered but wrapped in a zero-size/hidden container -
          only its popper (rendered through a portal, unaffected by the hidden container) is
          visible, explicitly anchored to the whole field container above (not just the small
          icon) via `slotProps.popper.anchorEl`, so it opens at the same position as the native
          mode's own popper - fixing both the old top-left bug (the whole picker, including its
          anchor, used to be hidden via `sx={{ display: 'none' }}`) and the visual mismatch
          between the two modes. Once a date is accepted here, the component switches to the
          native segmented field above on the next render. */}
      {isDatePickerOpen && (
        <div style={{ position: 'absolute', width: 0, height: 0, overflow: 'hidden' }} aria-hidden>
          <DateTimePicker
            open={isDatePickerOpen}
            onClose={() => setIsDatePickerOpen(false)}
            onAccept={handleChangeAbsoluteDateFilter}
            value={isValidDate(draft) ? new Date(draft) : null}
            slotProps={{
              textField: { tabIndex: -1 },
              popper: { anchorEl: fieldContainerRef.current },
            }}
          />
        </div>
      )}
      {shortcutsPopover}
    </div>
  );
};

export default RelativeDateInput;
