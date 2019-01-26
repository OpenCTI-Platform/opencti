import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { DatePicker } from 'material-ui-pickers';
import inject18n from './i18n';

class DatePickerField extends Component {
  render() {
    const { t, field, form, ...other } = this.props;
    const currentError = form.errors[field.name];
    return (
      <DatePicker
        keyboard
        clearable
        disablePast
        name={field.name}
        value={field.value}
        format='yyyy-MM-dd'
        helperText={currentError}
        error={Boolean(currentError)}
        onError={(_, error) => form.setFieldError(field.name, error)}
        onChange={date => form.setFieldValue(field.name, date, true)}
        mask={value => (value ? [/\d/, /\d/, '/', /\d/, /\d/, '/', /\d/, /\d/, /\d/, /\d/] : [])}
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
