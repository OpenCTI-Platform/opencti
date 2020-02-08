import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import Popover from '@material-ui/core/Popover';
import InputAdornment from '@material-ui/core/InputAdornment';
import { useField } from 'formik';
import { useFieldToTextField } from 'formik-material-ui';
import { ColorLens } from '@material-ui/icons';

const ColorPickerField = (props) => {
  const anchorEl = React.createRef();
  const [open, setOpen] = React.useState(false);
  const [field, meta, helpers] = useField(props);
  const customize = React.useCallback(
    ([callbackField, , callbackHelpers]) => ({
      onChange: (event) => {
        const { value } = event.target;
        callbackHelpers.setValue(value);
        if (typeof props.onChange === 'function') {
          props.onChange(callbackField.name, value);
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(callbackField.name);
        }
      },
      onBlur: (event) => {
        callbackHelpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(callbackField.name, event.target.value);
        }
      },
    }),
    [props],
  );
  const handleChange = (color) => {
    helpers.setValue(color.hex);
    if (typeof props.onChange === 'function') {
      props.onChange(field.name, color.hex);
    }
    if (typeof props.onSubmit === 'function') {
      props.onSubmit(field.name, color.hex);
    }
  };

  return (
    <div>
      <MuiTextField
        {...useFieldToTextField(props, customize)}
        ref={anchorEl}
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
