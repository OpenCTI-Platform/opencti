import React, { Component } from 'react';
import { SketchPicker } from 'react-color';
import IconButton from '@material-ui/core/IconButton';
import Popover from '@material-ui/core/Popover';
import InputAdornment from '@material-ui/core/InputAdornment';
import { ColorLens } from '@material-ui/icons';
import MuiTextField from '@material-ui/core/TextField';
import { useField } from 'formik';
import { useFieldToTextField } from 'formik-material-ui';

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
    const fieldProps = useFieldToTextField(this.props);
    const [, , helpers] = useField(this.props.name);
    return (
      <div>
        <MuiTextField
          {...fieldProps}
          ref={this.anchorEl}
          onChange={(event) => {
            const { value } = event.target;
            helpers.setValue(value);
            if (typeof this.props.onChange === 'function') {
              this.props.onChange(this.props.field.name, value);
            }
          }}
          onFocus={() => {
            if (typeof this.props.onFocus === 'function') {
              this.props.onFocus(this.props.field.name);
            }
          }}
          onKeyPress={(event) => {
            helpers.setTouched(true);
            if (
              typeof this.props.onSubmit === 'function'
              && event.key === 'Enter'
            ) {
              this.props.onSubmit(this.props.field.name, event.target.value);
            }
          }}
          onBlur={(event) => {
            helpers.setTouched(true);
            if (typeof this.props.onSubmit === 'function') {
              this.props.onSubmit(this.props.field.name, event.target.value);
            }
          }}
          classes={this.props.classes}
          className={this.props.className}
          InputProps={{
            endAdornment: (
              <InputAdornment position="end">
                <IconButton
                  aria-label="open"
                  onClick={this.handleOpen.bind(this)}
                >
                  <ColorLens />
                </IconButton>
              </InputAdornment>
            ),
          }}
        />
        <Popover
          open={this.state.open}
          anchorEl={this.anchorEl.current}
          onClose={this.handleClose.bind(this)}
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
            color={this.props.form.values[this.props.field.name]}
            onChangeComplete={this.handleChange.bind(this)}
          />
        </Popover>
      </div>
    );
  }
}

export default ColorPickerField;
