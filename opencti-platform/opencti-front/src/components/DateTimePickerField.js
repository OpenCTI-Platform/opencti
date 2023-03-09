import React from 'react';
import { KeyboardDateTimePicker, MuiPickersUtilsProvider } from '@material-ui/pickers';
import { fieldToKeyboardDatePicker } from 'formik-material-ui-pickers';
import { withStyles } from '@material-ui/core';
import MomentUtils from '@date-io/moment';
import { parse } from '../utils/Time';

const styles = {
  timeSeprator: {
    '& .MuiPickerDTToolbar-separator': {
      margin: '0px',
    },
  },
};

const DateTimePickerField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    classes,
  } = props;
  const internalOnAccept = React.useCallback(
    (date) => {
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, date.toISOString());
      }
    },
    [setTouched, onSubmit, name],
  );
  const internalOnChange = React.useCallback(
    (date) => {
      setFieldValue(name, date);
      if (typeof onChange === 'function') {
        onChange(name, date);
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
      setTouched(true);
      const { value } = event.target;
      if (typeof onSubmit === 'function') {
        onSubmit(name, parse(value).toISOString());
      }
    },
    [setTouched, onSubmit, name],
  );
  return (
    <MuiPickersUtilsProvider utils={MomentUtils}>
      <KeyboardDateTimePicker
        {...fieldToKeyboardDatePicker(props)}
        variant="inline"
        inputVariant='outlined'
        disableToolbar={false}
        autoOk={true}
        allowKeyboardControl={true}
        format="YYYY-MM-DD hh:mm"
        onAccept={internalOnAccept}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        className={classes.timeSeprator}
      />
    </MuiPickersUtilsProvider>
  );
};

export default withStyles(styles)(DateTimePickerField);
