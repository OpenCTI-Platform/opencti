/* eslint-disable */
/* Refactor */
import React from 'react';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import InputAdornment from '@material-ui/core/InputAdornment';
import Popover from '@material-ui/core/Popover';
import { useField, Field } from 'formik';
import { fieldToTextField } from 'formik-material-ui';
import CardContent from '@material-ui/core/CardContent';
import TextField from './TextField';
import { ColorLens } from '@material-ui/icons';
import { makeStyles } from '@material-ui/core/styles';

const useStyles = makeStyles((theme) => ({
  margin: {
    margin: theme.spacing(1),
  },
}));

const ColorPickerField = (props) => {
  const [anchorEl, setAnchorEl] = React.useState(null);
  const [color, setColor] = React.useState('');
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
  } = props;
  const [, meta] = useField(name);
  const open = Boolean(anchorEl);
  const classes = useStyles();

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

  const handleOpen = event => {
    setAnchorEl(event.currentTarget);
  }

  const handleClose = () => {
    setAnchorEl(null);
  }
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
          className={classes.margin}
          InputProps={{
            endAdornment: (
              <InputAdornment position="end">
                <IconButton  aria-label="open" onClick={handleOpen}>
                  <ColorLens />
                </IconButton>
              </InputAdornment>
            ),
          }}
        />
      </CardContent>
      <Popover
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'left',
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
