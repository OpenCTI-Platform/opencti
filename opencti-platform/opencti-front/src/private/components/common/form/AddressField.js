/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import InputAdornment from '@material-ui/core/InputAdornment';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { Edit } from '@material-ui/icons';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '85px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  inputTextField: {
    color: 'white',
  },
  textField: {
    background: theme.palette.header.background,
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
});

class AddressField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: '',
      error: false,
      ipAddress: [...this.props.addressValues],
    };
  }

  handleAddAddress() {
    if(this.props.name !== 'installed_on' && this.props.name !== 'related_risks' && this.props.name !== 'installed_software') {
      if (!this.props.validation.test(this.state.value)) {
        return this.setState({ error: true });
       }
    }    
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.ipAddress.every((value) => value !== this.state.value)) {
      this.state.ipAddress.push(this.state.value);
    }
    this.setState({ value: '' });
  }

  handleSubmit() {
    this.setState({ open: false, value: '' }, () => (
      this.props.setFieldValue(this.props.name, this.state.ipAddress)
    ));
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((value, i) => i !== key) });
  }

  render() {
    const {
      t, fldt, classes, name, title, helperText,
    } = this.props;
    const {
      error, ipAddress,
    } = this.state;
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography>
            {title && t(title)}
          </Typography>
          <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
            <Tooltip title={t('Baseline Configuration Name')} >
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          <IconButton size='small' onClick={() => this.setState({ open: true })}>
            <Edit fontSize='small' />
          </IconButton>
        </div>
        <Field
          component={NewTextField}
          name={name}
          fullWidth={true}
          disabled={true}
          multiline={true}
          rows="3"
          value={ipAddress}
          className={classes.textField}
          InputProps={{
            className: classes.inputTextField,
          }}
          variant='outlined'
        />
        <Dialog
          open={this.state.open}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>
            {t(`Edit ${title}(es)`)}
          </DialogContent>
          <DialogContent style={{ overflow: 'hidden' }}>
            <TextField
              error={error}
              helperText={error ? helperText : ''}
              onChange={(event) => this.setState({ value: event.target.value })}
              onFocus={() => this.setState({ error: false })}
              fullWidth={true}
              value={this.state.value}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      edge="end"
                      onClick={this.handleAddAddress.bind(this)}
                    >
                      <AddIcon />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </DialogContent>
          <DialogContent>
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {ipAddress.map((address, key) => (
                    <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography>
                        {address}
                      </Typography>
                      <IconButton onClick={this.handleDeleteAddress.bind(this, key)}>
                        <Delete />
                      </IconButton>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => this.setState({ open: false, value: '' })}
            >
              {t('Cancel')}
            </Button>
            <Button
              disabled={!ipAddress.length}
              variant='contained'
              onClick={this.handleSubmit.bind(this)}
              color="primary"
            >
              {t('Submit')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

AddressField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(AddressField);
