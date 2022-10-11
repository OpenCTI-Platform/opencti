import React from 'react';
import Grid from '@mui/material/Grid';
import MuiTextField from '@mui/material/TextField';
import { fieldToTextField } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';

const DynamicResolutionField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field,
    onChange,
    onFocus,
    onSubmit,
    title,
  } = props;
  const internalOnChange = React.useCallback(
    (event) => {
      const { value } = event.target;
      setFieldValue(field.name, value);
      if (typeof onChange === 'function') {
        onChange(field.name, value);
      }
    },
    [onChange, setFieldValue, field.name],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(field.name);
    }
  }, [onFocus, field.name]);
  const internalOnBlur = React.useCallback(
    (event) => {
      const { value } = event.target;
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(field.name, value || '');
      }
    },
    [onSubmit, setTouched, field.name],
  );
  const [, meta] = useField(field.name);
  return (
    <div>
      <Typography variant="h2">{title}</Typography>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={6}>
          <MuiTextField
            {...fieldToTextField(props)}
            error={!isNil(meta.error)}
            helperText={props.helperText}
            onChange={internalOnChange}
            onFocus={internalOnFocus}
            onBlur={internalOnBlur}
            multiline={true}
            minRows={6}
            inputProps={{ style: { lineHeight: '34px' } }}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <List style={{ marginTop: 10 }}>
            {field.value
              .split('\n')
              .filter((n) => n.length > 1)
              .map((val) => (
                <ListItem key={val} dense={true} divider={true}>
                  <ListItemIcon>
                    <BullseyeArrow />
                  </ListItemIcon>
                  <ListItemText primary={val} />
                </ListItem>
              ))}
          </List>
        </Grid>
      </Grid>
    </div>
  );
};

export default DynamicResolutionField;
