import React, { useEffect, useState } from 'react';
import {
  Card, CardActions, CardContent, CardHeader, FormControl, FormGroup, Paper, TextField, Typography,
} from '@material-ui/core';
import PropTypes from 'prop-types';
import Button from '@material-ui/core/Button';
import { updateScan } from '../../../../services/scan.service';
import { toastAxiosError, toastSuccess } from '../../../../utils/bakedToast';

const UpdateScan = (props) => {
  const [newName, setNewName] = useState(null);
  const [handling, setHandling] = useState(false);
  const [errors, setErrors] = useState({ name: 'value is required' });
  const [validForm, setValidForm] = useState(false);

  function handleOnClose(success) {
    props.onClose?.(success);
  }

  function handleNameChange(value) {
    setNewName(value);
    if (value === undefined) {
      errors.name = 'value is required';
    } else if (value.length < 3) {
      errors.name = 'value must be at least 3 characters';
    } else {
      errors.name = null;
    }
    setErrors(errors);
  }

  function submitForm() {
    setHandling(true);
    updateScan(props.scan.id, props.clientId, { scan_name: newName })
      .then(() => {
        setHandling(false);
        toastSuccess('Scan updated');
        handleOnClose(true);
      })
      .catch((err) => {
        console.error(err);
        toastAxiosError('Failed to update scan');
        setHandling(false);
      });
  }

  useEffect(() => {
    if (Object.values(errors).filter((v) => v != null).length === 0) {
      setValidForm(true);
    } else {
      setValidForm(false);
    }
  }, [errors, newName]);

  return (
    <Paper elevation={2} style={{ width: 400 }}>
      <Card>
        <CardHeader title={`Edit ${props.scan.scan_name}`}/>
        <CardContent>
          <FormGroup fullwidth>
            <FormControl>
              <TextField variant={'filled'} label={'Name'} onChange={(e) => handleNameChange(e.target.value)}/>
            </FormControl>
          </FormGroup>
        </CardContent>
        <CardActions style={{ justifyContent: 'right' }}>
          <Button
            size="small"
            color="secondary"
            disabled={handling}
            onClick={() => handleOnClose(false)}
          >
            Cancel
          </Button>
          <Button
            size="small"
            color="primary"
            disabled={handling || !validForm}
            onClick={() => submitForm()}
          >
            Submit
          </Button>
        </CardActions>
      </Card>
    </Paper>
  );
};

UpdateScan.propTypes = {
  onClose: PropTypes.func,
  clientId: PropTypes.string,
  scan: PropTypes.object,
};

export default UpdateScan;
