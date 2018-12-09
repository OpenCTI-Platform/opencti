import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import classNames from 'classnames';
import Select from 'react-select';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import TextField from '@material-ui/core/TextField';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import CancelIcon from '@material-ui/icons/Cancel';
import { emphasize } from '@material-ui/core/styles/colorManipulator';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import inject18n from './i18n';

const styles = theme => ({
  root: {
    flexGrow: 1,
  },
  input: {
    display: 'flex',
    padding: 0,
    minHeight: 40,
  },
  valueContainer: {
    display: 'flex',
    flexWrap: 'wrap',
    flex: 1,
    alignItems: 'center',
    overflow: 'hidden',
  },
  chip: {
    margin: `${theme.spacing.unit / 2}px ${theme.spacing.unit / 4}px`,
  },
  chipFocused: {
    backgroundColor: emphasize(
      theme.palette.type === 'light' ? theme.palette.grey[300] : theme.palette.grey[700],
      0.08,
    ),
  },
  noOptionsMessage: {
    padding: `${theme.spacing.unit}px ${theme.spacing.unit * 2}px`,
  },
  singleValue: {
    fontSize: 16,
  },
  placeholder: {
    position: 'absolute',
    left: 2,
    fontSize: 16,
  },
  paper: {
    position: 'absolute',
    zIndex: 1,
    marginTop: theme.spacing.unit,
    left: 0,
    right: 0,
  },
  divider: {
    height: theme.spacing.unit * 2,
  },
});

function NoOptionsMessage(props) {
  return (
    <Typography
      color='textSecondary'
      className={props.selectProps.classes.noOptionsMessage}
      {...props.innerProps}
    >
      {props.children}
    </Typography>
  );
}

function inputComponent({ inputRef, ...props }) {
  return <div ref={inputRef} {...props} />;
}

function Control(props) {
  return (
    <TextField
      fullWidth={true}
      InputProps={{
        inputComponent,
        inputProps: {
          disabled: props.isDisabled,
          className: props.selectProps.classes.input,
          inputRef: props.innerRef,
          children: props.children,
          ...props.innerProps,
        },
      }}
      {...props.selectProps.textFieldProps}
    />
  );
}

function Option(props) {
  return (
    <MenuItem
      buttonRef={props.innerRef}
      selected={props.isFocused}
      component="div"
      style={{
        fontWeight: props.isSelected ? 500 : 400,
      }}
      {...props.innerProps}
    >
      {props.children}
    </MenuItem>
  );
}

function Placeholder(props) {
  return (
    <Typography
      color="textSecondary"
      className={props.selectProps.classes.placeholder}
      {...props.innerProps}
    >
      {props.children}
    </Typography>
  );
}

function SingleValue(props) {
  return (
    <Typography className={props.selectProps.classes.singleValue} {...props.innerProps}>
      {props.children}
    </Typography>
  );
}

function ValueContainer(props) {
  return <div className={props.selectProps.classes.valueContainer}>{props.children}</div>;
}

function MultiValue(props) {
  return (
    <Chip
      tabIndex={-1}
      label={props.children}
      className={classNames(props.selectProps.classes.chip, {
        [props.selectProps.classes.chipFocused]: props.isFocused,
      })}
      onDelete={props.removeProps.onClick}

      deleteIcon={<CancelIcon {...props.removeProps} />}
    />
  );
}

function Menu(props) {
  return (
    <Paper square className={props.selectProps.classes.paper} {...props.innerProps}>
      {props.children}
    </Paper>
  );
}

const components = {
  Control,
  Menu,
  MultiValue,
  NoOptionsMessage,
  Option,
  Placeholder,
  SingleValue,
  ValueContainer,
};

class Autocomplete extends Component {
  render() {
    const {
      required,
      classes,
      theme,
      t,
      label,
      field,
      form: {
        dirty,
        errors,
        values,
        setFieldValue,
        isSubmitting,
      },
      options,
      onInputChange,
      onChange,
      onFocus,
    } = this.props;
    const errorText = errors[field.name];
    const hasError = dirty && errorText !== undefined;

    const selectStyles = {
      input: base => ({
        ...base,
        color: theme.palette.text.primary,
        '& input': {
          font: 'inherit',
        },
      }),
    };

    return (
      <div className={classes.root}>
        <FormControl
          fullWidth
          error={hasError}
          required={required}
          disabled={isSubmitting}
          style={{ marginTop: '10px' }}
        >
          <Select
            classes={classes}
            styles={selectStyles}
            textFieldProps={{
              onChange: onInputChange,
              label: values[field.name] ? values[field.name].length > 0 ? label : ' ' : ' ',
              error: hasError,
              InputLabelProps: {
                shrink: true,
              },
            }}
            options={options}
            components={components}
            value={values[field.name]}
            onChange={(values) => {
              setFieldValue(field.name, values);
              if (typeof onChange === 'function') {
                onChange(field.name, values);
              }
            }}
            onFocus={() => {
              if (typeof onFocus === 'function') {
                onFocus(field.name);
              }
            }}
            placeholder={label}
            isMulti={true}
            openMenuOnClick={false}
            isDisabled={isSubmitting}
            noOptionsMessage={() => t('No available options')}
          />
          {hasError && <FormHelperText>{errorText}</FormHelperText>}
        </FormControl>
      </div>
    );
  }
}

Autocomplete.propTypes = {
  required: PropTypes.bool,
  classes: PropTypes.object.isRequired,
  theme: PropTypes.object.isRequired,
  t: PropTypes.func,
  name: PropTypes.string,
  label: PropTypes.string,
  options: PropTypes.array,
  field: PropTypes.object,
  form: PropTypes.shape({
    dirty: PropTypes.bool,
    errors: PropTypes.object,
    setFieldValue: PropTypes.func,
  }),
  onInputChange: PropTypes.func,
  onChange: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(Autocomplete);
