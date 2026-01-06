import { ReactNode, useCallback } from 'react';
import { Add } from '@mui/icons-material';
import { TextField, Autocomplete, AutocompleteProps, TextFieldProps, AutocompleteValue } from '@mui/material';
import IconButton from '@common/button/IconButton';
import { FieldProps, useField } from 'formik';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';
import { isNilField } from '../utils/utils';
import { FieldOption } from '../utils/field';
import { fieldToAutocomplete } from 'formik-mui';

type Bool = boolean | undefined;
type PossibleValue = FieldOption | string;

export type AutocompleteFieldProps<
  M extends Bool = true,
  Value extends PossibleValue = FieldOption,
  DC extends Bool = boolean,
  FSolo extends Bool = false,
> = Omit<AutocompleteProps<Value, M, DC, FSolo>, 'onChange' | 'onBlur' | 'onFocus' | 'renderInput'>
  & FieldProps<Value>
  & {
    optionLength?: number;
    required?: boolean;
    endAdornment?: ReactNode;
    textfieldprops?: TextFieldProps;
    onFocus?: (name: string) => void;
    onChange?: (name: string, value: AutocompleteValue<Value, M, DC, FSolo>) => void;
    onInternalChange?: (name: string, value: AutocompleteValue<Value, M, DC, FSolo>) => void;
    openCreate?: () => void;
  };

const AutocompleteField = <
  M extends Bool = true,
  Value extends PossibleValue = FieldOption,
  DC extends Bool = boolean,
  FSolo extends Bool = false,
>({
  optionLength = 40,
  required = false,
  onChange,
  onFocus,
  onInternalChange,
  openCreate,
  ...muiProps
}: AutocompleteFieldProps<M, Value, DC, FSolo>) => {
  type MuiProps = AutocompleteProps<Value, M, DC, FSolo>;

  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    noOptionsText,
    renderOption,
    isOptionEqualToValue,
    textfieldprops,
    getOptionLabel,
    endAdornment,
    disabled,
  } = muiProps;

  const [, meta] = useField(name);
  const { t_i18n } = useFormatter();

  const internalOnChange = useCallback<NonNullable<MuiProps['onChange']>>((_, value) => {
    if (onInternalChange) {
      onInternalChange(name, value);
    } else {
      setFieldValue(name, value);
      onChange?.(name, value);
    }
  }, [setFieldValue, name, onChange, onInternalChange]);

  const internalOnFocus = useCallback<NonNullable<MuiProps['onFocus']>>(() => {
    onFocus?.(name);
  }, [onFocus, name]);

  const internalOnBlur = useCallback<NonNullable<MuiProps['onBlur']>>(() => {
    setFieldTouched(name, true);
  }, [setFieldTouched]);

  const defaultOptionToValue = (option: Value, value: Value) => {
    const optionVal = typeof option === 'object' ? option.value : option;
    const valueVal = typeof value === 'object' ? value.value : value;
    return optionVal === valueVal;
  };

  const defaultGetOptionLabel: MuiProps['getOptionLabel'] = (option) => {
    return typeof option === 'object'
      ? truncate(option.label, optionLength)
      : truncate(option, optionLength);
  };

  const helperText = textfieldprops?.helperText;
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);
  const fieldProps = fieldToAutocomplete({
    ...muiProps,
    renderInput: ({ inputProps: { value, ...inputProps }, InputProps, ...params }) => (
      <TextField
        {...{ ...params, inputProps }}
        {...textfieldprops}
        slotProps={{
          input: {
            ...InputProps,
            endAdornment: endAdornment ?? InputProps.endAdornment,
          },
        }}
        value={value}
        name={name}
        required={required}
        fullWidth
        error={showError}
        helperText={showError ? meta.error : helperText}
      />
    ),
  });

  return (
    <div style={{ position: 'relative' }}>
      <Autocomplete
        size="small"
        selectOnFocus
        autoHighlight
        handleHomeEndKeys
        getOptionLabel={getOptionLabel || defaultGetOptionLabel}
        noOptionsText={noOptionsText}
        {...fieldProps}
        renderOption={renderOption}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        isOptionEqualToValue={isOptionEqualToValue ?? defaultOptionToValue}
        slotProps={{
          paper: {
            elevation: 2,
          },
        }}
      />

      {openCreate && (
        <IconButton
          disabled={disabled}
          onClick={() => openCreate()}
          style={{ position: 'absolute', top: 5, right: 35 }}
          title={t_i18n('Add')}
        >
          <Add />
        </IconButton>
      )}
    </div>
  );
};

export default AutocompleteField;
