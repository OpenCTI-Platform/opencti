import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import TextField from '@mui/material/TextField';
import { IconButton } from '@filigran/design-system';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { CalendarIcon } from '@mui/x-date-pickers/icons';
import { Link } from 'react-router';
import { useFormatter } from '../i18n';
import { isValidDate, RELATIVE_DATE_REGEX } from '../../utils/String';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface RelativeDateInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  label: string;
  valueOrder: number;
  dateInput: string[];
  setDateInput: (value: string[]) => void;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  label,
  valueOrder,
  dateInput,
  setDateInput,
}) => {
  const { t_i18n, smhd } = useFormatter();
  const [isDatePickerOpen, setIsDatePickerOpen] = useState(false);
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
  // Valid date typed in the native field but not accepted yet; saved when the field loses focus.
  const pendingDate = useRef<Date | null>(null);

  useEffect(() => {
    setDraft(dateInput[valueOrder]);
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
  // go back to picking a real date.
  const isAbsoluteMode = isValidDate(committedValue);

  if (isAbsoluteMode) {
    return (
      <div style={{ display: 'flex', flex: 1, minWidth: 0, alignItems: 'center' }}>
        <DateTimePicker
          label={label}
          value={new Date(committedValue)}
          onChange={(value) => {
            pendingDate.current = value && !Number.isNaN(value.getTime()) ? value : null;
          }}
          onAccept={(value) => {
            pendingDate.current = null;
            if (value) {
              handleChangeRangeDateFilter(value.toISOString());
            }
          }}
          slotProps={{
            textField: {
              onBlur: () => {
                if (pendingDate.current) {
                  handleChangeRangeDateFilter(pendingDate.current.toISOString());
                  pendingDate.current = null;
                }
              },
              id: filter?.id ?? `${filterKey}-id`,
              size: 'small',
              variant: 'outlined',
              fullWidth: true,
              error: errorMessage !== undefined,
              helperText: errorMessage,
            },
          }}
        />
      </div>
    );
  }

  const displayValue = !isEditing && isValidDate(draft) ? smhd(draft) : draft;

  return (
    <div ref={fieldContainerRef} style={{ display: 'flex', flex: 1, minWidth: 0, alignItems: 'center' }}>
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
              <IconButton
                size="md"
                priority="tertiary"
                onClick={() => setIsDatePickerOpen(true)}
                aria-label="open date picker"
                icon={<CalendarIcon fontSize="medium" />}
              />
            ),
          },
        }}
      />
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
    </div>
  );
};

export default RelativeDateInput;
