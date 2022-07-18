/* eslint-disable */
/* Refactor */
import React from 'react';
// import TextField from '@material-ui/core/TextField';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import Popover from '@material-ui/core/Popover';
import InputAdornment from '@material-ui/core/InputAdornment';
import { useField, Field } from 'formik';
import { fieldToTextField } from 'formik-material-ui';
import Box from '@material-ui/core/Box';
import CardContent from '@material-ui/core/CardContent';
import TextField from './TextField';
import { ColorLens, Add } from '@material-ui/icons';

const ColorPickerField = (props) => {
  const anchorEl = React.createRef();
  const [open, setOpen] = React.useState(false);
  const [color, setColor] = React.useState('');
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
      setColor(value);
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
    setColor(color.hex);
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
    <div style={{ margin: '10px 0' }}>
      <CardContent
        {...fieldToTextField(props)}
        ref={anchorEl}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        style={{ display: 'flex', padding: '0px' }}
      >
        <Field
          component={TextField}
          name="color"
          label='Color'
          fullWidth={true}
        />
        <IconButton style={{ position: 'absolute', right: '20px' }} aria-label="open" onClick={() => setOpen(true)}>
          <ColorLens />
        </IconButton>
      </CardContent>
      {/* <MuiTextField
        {...fieldToTextField(props)}
        ref={anchorEl}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        InputProps={{
          endAdornment: (
            <InputAdornment>
              <IconButton aria-label="open" onClick={() => setOpen(true)}>
                <Add />
              </IconButton>
            </InputAdornment>
          ),
          startAdornment: (
            <InputAdornment>
                <IconButton>
                    <Box
                    sx={{
                      width: 30,
                      height: 30,
                      bgcolor: 'primary.main',
                    }}
                    style={{ borderRadius: '50%' }}/>
                </IconButton>
            </InputAdornment>
          ),
        }}
      /> */}
      <Popover
        open={open}
        anchorEl={anchorEl.current}
        onClose={() => setOpen(false)}
        anchorOrigin={{
          vertical: 'bottom',
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
