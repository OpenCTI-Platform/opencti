import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { KeyboardDatePicker } from '@material-ui/pickers';
import { dateFormat } from '../utils/Time';
import inject18n from './i18n';

class DatePickerField extends Component {
  constructor(props) {
    super(props);
    this.currentDate = this.props.field.value;
    this.state = { focused: false };
  }

  render() {
    const {
      t,
      n,
      fld,
      fsd,
      md,
      fd,
      yd,
      nsd,
      nsdt,
      field,
      form,
      onFocus,
      onSubmit,
      ...other
    } = this.props;
    return (
      <KeyboardDatePicker
        variant="inline"
        disableToolbar={false}
        autoOk={true}
        allowKeyboardControl={true}
        name={field.name}
        value={field.value}
        onFocus={() => {
          this.setState({ focused: true });
          if (typeof onFocus === 'function') {
            onFocus(field.name);
          }
        }}
        onBlur={(event) => {
          this.setState({ focused: false });
          form.setFieldTouched(field.name, true, true);
          if (
            typeof onSubmit === 'function'
            && this.currentDate !== event.target.value
          ) {
            onSubmit(field.name, dateFormat(event.target.value));
            this.currentDate = event.target.value;
          }
        }}
        onKeyPress={(event) => {
          this.setState({ focused: true });
          if (
            typeof onSubmit === 'function'
            && event.key === 'Enter'
            && this.currentDate !== event.target.value
          ) {
            onSubmit(field.name, dateFormat(event.target.value));
            this.currentDate = event.target.value;
          }
        }}
        onChange={(date) => {
          form.setFieldValue(field.name, date, true);
          if (
            this.state.focused === false
            && typeof onSubmit === 'function'
            && this.currentDate !== date
          ) {
            onSubmit(field.name, dateFormat(date));
            this.currentDate = date;
          }
        }}
        format="YYYY-MM-DD"
        error={
          form.errors[field.name] !== undefined && form.touched[field.name]
        }
        invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
        {...other}
      />
    );
  }
}

DatePickerField.propTypes = {
  t: PropTypes.func.isRequired,
  field: PropTypes.object,
  form: PropTypes.object,
};

export default inject18n(DatePickerField);
