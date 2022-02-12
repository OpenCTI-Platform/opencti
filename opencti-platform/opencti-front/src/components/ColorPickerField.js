import React from 'react';
import MuiTextField from '@mui/material/TextField';
import { SketchPicker } from 'react-color';
import IconButton from '@mui/material/IconButton';
import Popover from '@mui/material/Popover';
import InputAdornment from '@mui/material/InputAdornment';
import { useField } from 'formik';
import { fieldToTextField } from 'formik-mui';
import { ColorLens } from '@mui/icons-material';

const ColorPickerField = (props) => {
  const anchorEl = React.createRef();
  const [open, setOpen] = React.useState(false);
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
  } = props;
  const [, meta] = useField(name);
  const internalOnChange = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [setFieldValue, onChange, name],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(
    (event) => {
      const { value } = event.target;
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [setTouched, onSubmit, name],
  );
  const handleChange = (color) => {
    setTouched(true);
    setFieldValue(name, color && color.hex ? color.hex : '');
    if (typeof onChange === 'function') {
      onChange(name, color && color.hex ? color.hex : '');
    }
    if (typeof onSubmit === 'function') {
      onSubmit(name, color && color.hex ? color.hex : '');
    }
  };

  return (
    <div>
      <MuiTextField
        {...fieldToTextField(props)}
        ref={anchorEl}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        InputProps={{
          endAdornment: (
            <InputAdornment position="end">
              <IconButton
                aria-label="open"
                onClick={() => setOpen(true)}
                size="large"
              >
                <ColorLens />
              </IconButton>
            </InputAdornment>
          ),
        }}
      />
      <Popover
        open={open}
        anchorEl={anchorEl.current}
        onClose={() => setOpen(false)}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
      >
        <SketchPicker
          color={meta.value || ''}
          onChangeComplete={(color) => handleChange(color)}
        />
      </Popover>
    </div>
  );
};

export default ColorPickerField;
