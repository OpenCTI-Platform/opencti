import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { fieldToTextField } from 'formik-material-ui';
import { useField } from 'formik';
import { makeStyles } from '@material-ui/core/styles';
import { isNil } from 'ramda';
import Delete from '@material-ui/icons/Delete';
import { IconButton } from '@material-ui/core';
import Link from '@material-ui/core/Link';
import LaunchIcon from '@material-ui/icons/Launch';
import { useHistory } from 'react-router-dom';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';

const useStyles = makeStyles((theme) => ({
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    borderRadius: '5px',
    lineHeight: '20px',
    maxHeight: '97px',
    overflow: 'hidden',
    padding: '5px 5px 10px 15px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    maxHeight: '132px',
    height: '160px',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
    maxHeight: '132px',
    height: '160px',
  },
  link: {
    textAlign: 'left',
    fontSize: '1rem',
    display: 'flex',
    alignItems: 'center',
    minWidth: '50px',
    width: '100%',
  },
  launchIcon: {
    marginRight: '1%',
  },
  linkTitle: {
    color: '#fff',
    minWidth: 'fit-content',
  },
  input: {
    display: 'block',
    maxHeight: '132px',
    overflowY: 'auto',
    height: '160px',
    paddingTop: 0,
  },
  hideText: {
    '& .MuiInputBase-input': {
      display: 'none',
    },
  },
}));

const customTextField = (
  value,
  id,
  fieldName,
  classes,
  history,
  link,
  handleDelete,
  index,
) => (
  <div style={{ display: 'flex' }}>
    <Link
      key={index}
      component="button"
      variant="body2"
      className={classes.link}
      onClick={() => history.push(`${link}/${id}`)}
    >
      <LaunchIcon fontSize="small" className={classes.launchIcon} />
      <div className={classes.linkTitle}>{value}</div>
    </Link>
    {['installed_hardware', 'installed_software'].includes(fieldName) && (
      <IconButton
        style={{ padding: '5px' }}
        onClick={() => handleDelete(index)}
      >
        <Delete />
      </IconButton>
    )}
  </div>
);

const HyperLinks = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    detectDuplicate,
  } = props;

  const history = useHistory();
  const classes = useStyles();

  const internalOnChange = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value);
      }
    },
    [onChange, setFieldValue, name],
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
    [onSubmit, setTouched, name],
  );
  const [, meta] = useField(name);
  return (
    <div className={classes.scrollBg}>
      <div className={classes.scrollDiv}>
        <div className={classes.scrollObj}>
          <MuiTextField
            {...fieldToTextField(props)}
            value={null}
            error={!isNil(meta.error)}
            helperText={
              // eslint-disable-next-line no-nested-ternary
              detectDuplicate && (isNil(meta.error) || !meta.touched) ? (
                <StixDomainObjectDetectDuplicate
                  types={detectDuplicate}
                  value={meta.value}
                />
              ) : meta.error ? (
                meta.error
              ) : (
                props.helperText
              )
            }
            onChange={internalOnChange}
            onFocus={internalOnFocus}
            onBlur={internalOnBlur}
            variant="standard"
            fullWidth={true}
            multiline={true}
            className={classes.hideText}
            InputProps={{
              classes: {
                root: classes.input,
              },
              disableUnderline: true,
              startAdornment:
              // eslint-disable-next-line max-len
              props.value.map((n, index) => customTextField(n.name, n.id, props.field.name, classes, history, props.link, props.handleDelete, index)),
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default HyperLinks;
