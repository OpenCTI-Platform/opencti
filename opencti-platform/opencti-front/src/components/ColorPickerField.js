import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import Popover from '@material-ui/core/Popover';
import InputAdornment from '@material-ui/core/InputAdornment';
import { useField } from 'formik';
import { fieldToTextField } from 'formik-material-ui';
import Box from '@material-ui/core/Box';
import CardContent from '@material-ui/core/CardContent';
import { ColorLens, Add } from '@material-ui/icons';

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
    <div style={{ borderBottom: '1px solid grey', margin: '20px 0' }}>
      <CardContent
       {...fieldToTextField(props)}
        ref={anchorEl}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        style={{ display: 'flex', padding: '0px' }}
      >
              <Box sx={{
                width: 40,
                height: 40,
                bgcolor: 'primary.main',
                borderRadius: '50%',
              }}
              style={{ marginRight: '8px', cursor: 'pointer' }}
                />
              <Box sx={{
                width: 40,
                height: 40,
                bgcolor: 'primary.dark',
                borderRadius: '50%',
              }}
               style={{ marginRight: '8px', cursor: 'pointer' }}
                />
              <Box sx={{
                width: 40,
                height: 40,
                bgcolor: 'secondary.main',
                borderRadius: '50%',
              }}
              style={{ marginRight: '8px', cursor: 'pointer' }}
                />
              <IconButton aria-label="open" onClick={() => setOpen(true)}>
                <Add />
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
