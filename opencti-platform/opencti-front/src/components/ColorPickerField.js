import React, { Component } from 'react';
import { SketchPicker } from 'react-color';
import ClickAwayListener from '@material-ui/core/ClickAwayListener';
import Paper from '@material-ui/core/Paper';
import MuiTextField from '@material-ui/core/TextField';
import { fieldToTextField } from 'formik-material-ui';

class ColorPickerField extends Component {
  constructor(props) {
    super(props);
    this.anchorEl = React.createRef();
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleChange(color) {
    this.props.form.setFieldValue(this.props.field.name, color.hex);
    if (typeof this.props.onChange === 'function') {
      this.props.onChange(this.props.field.name, color.hex);
    }
    if (typeof this.props.onSubmit === 'function') {
      this.props.onSubmit(this.props.field.name, color.hex);
    }
  }

  render() {
    return (
      <ClickAwayListener onClickAway={this.handleClose.bind(this)}>
        <div style={{ position: 'relative' }}>
          <MuiTextField
            {...fieldToTextField(this.props)}
            ref={this.anchorEl}
            onChange={(event) => {
              const { value } = event.target;
              this.props.form.setFieldValue(this.props.field.name, value);
              if (typeof this.props.onChange === 'function') {
                this.props.onChange(this.props.field.name, value);
              }
            }}
            onFocus={() => {
              this.handleOpen();
              if (typeof this.props.onFocus === 'function') {
                this.props.onFocus(this.props.field.name);
              }
            }}
            onKeyPress={(event) => {
              this.props.form.setFieldTouched(
                this.props.field.name,
                true,
                true,
              );
              if (
                typeof this.props.onSubmit === 'function'
                && event.key === 'Enter'
              ) {
                this.props.onSubmit(this.props.field.name, event.target.value);
              }
            }}
            onBlur={(event) => {
              this.props.form.setFieldTouched(
                this.props.field.name,
                true,
                true,
              );
              if (typeof this.props.onSubmit === 'function') {
                this.props.onSubmit(this.props.field.name, event.target.value);
              }
            }}
            classes={this.props.classes}
            className={this.props.className}
          />
          {this.state.open ? (
            <Paper style={{ position: 'absolute', top: 75 }}>
              <SketchPicker
                color={this.props.form.values[this.props.field.name]}
                onChangeComplete={this.handleChange.bind(this)}
              />
            </Paper>
          ) : (
            ''
          )}
        </div>
      </ClickAwayListener>
    );
  }
}

export default ColorPickerField;
