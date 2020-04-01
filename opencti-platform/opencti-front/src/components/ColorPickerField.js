import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import Popover from '@material-ui/core/Popover';
import InputAdornment from '@material-ui/core/InputAdornment';
import { useField } from 'formik';
import { fieldToTextField } from 'formik-material-ui';
import { ColorLens } from '@material-ui/icons';

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
    setFieldValue(name, color.hex);
    if (typeof onChange === 'function') {
      onChange(name, color.hex);
    }
    if (typeof onSubmit === 'function') {
      onSubmit(name, color.hex);
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
              <IconButton aria-label="open" onClick={() => setOpen(true)}>
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
          color={meta.value}
          onChangeComplete={(color) => handleChange(color)}
        />
      </Popover>
    </div>
  );
};

export default ColorPickerField;
