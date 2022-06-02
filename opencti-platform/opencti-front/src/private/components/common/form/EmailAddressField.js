/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import Edit from '@material-ui/icons/Edit';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  dataEntities: {
    width: '150px',
  },
  dataSelect: {
    display: 'flex',
    alignItems: 'center',
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

class EmailAddressField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      editOpen: false,
      value: '',
      error: false,
      editValueKey: '',
      emailAddress: [...this.props.addressValues],
    };
  }

  handleAddAddress() {
    if (!this.props.validation.test(this.state.value)) {
      return this.setState({ error: true });
    }
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.emailAddress.every((value) => value !== this.state.value)) {
      this.state.emailAddress.push( this.state.value );
    }
    this.setState({ value: '', open: false }, this.handleSubmit());
  }

  handleEditAddress() {
    if (!this.props.validation.test(this.state.value)) {
      return this.setState({ error: true });
    }
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.emailAddress.every((value) => value !== this.state.value)) {
      this.state.emailAddress[this.state.editValueKey] = this.state.value;
    }
    this.setState({ value: '', editOpen: false }, this.handleSubmit());
  }

  handleSubmit() {
    this.props.setFieldValue(this.props.name, this.state.emailAddress);
  }

  handleEditionAddress(key) {
    const editValue = this.state.emailAddress.filter((v, i) => i === key)[0];
    this.setState({
      value: editValue,
      editValueKey: key,
      editOpen: true,
    })
  }

  handleDeleteAddress(key) {
    this.setState({ emailAddress: this.state.emailAddress.filter((value, i) => i !== key) }, this.handleSubmit());
  }

  render() {
    const {
      t, fldt, classes, name, title, helperText,
    } = this.props;
    const {
      error,
    } = this.state;
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography color='textSecondary'>
            {title && t(title)}
          </Typography>
          <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
            <Tooltip title={t('Baseline Configuration Name')} >
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          <IconButton size='small' onClick={() => this.setState({ open: true })}>
            <AddIcon />
          </IconButton>
        </div>
        <div className={classes.scrollBg}>
          <div className={classes.scrollDiv}>
            <div className={classes.scrollObj}>
              {this.state.emailAddress.map((address, key) => (
                <div key={key} style={{ display: 'grid', gridTemplateColumns: '75% 1fr' }}>
                  <div style={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                    <Typography>
                      {(address && t(address.substr(0, 15).concat('...')))}
                    </Typography>
                  </div>
                  <div style={{ display: 'flex' }}>
                    <IconButton
                      size='small'
                      onClick={this.handleEditionAddress.bind(this, key)}
                    >
                      <Edit />
                    </IconButton>
                    <IconButton
                      size='small'
                      onClick={this.handleDeleteAddress.bind(this, key)}
                    >
                      <Delete />
                    </IconButton>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <Dialog
          open={this.state.open}
          onClose={() => this.setState({ open: false })}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>
            {t(`Add or Edit ${title}`)}
          </DialogContent>
          <DialogContent style={{ overflow: 'hidden', display: 'flex', alignItems: 'end' }}>
              <TextField
                error={error}
                label='Enter Email Address'
                helperText={error ? helperText : ''}
                onChange={(event) => this.setState({ value: event.target.value })}
                onFocus={() => this.setState({ error: false })}
                fullWidth={true}
                value={this.state.value}
              />
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => this.setState({ open: false, value: '' })}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant='contained'
              onClick={this.handleAddAddress.bind(this)}
              color="primary"
            >
              {t('Submit')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          open={this.state.editOpen}
          onClose={() => this.setState({ editOpen: false })}
          fullWidth={true}
          maxWidth='sm'
        >
          <DialogContent>
            {t(`Add or Edit ${title}`)}
          </DialogContent>
          <DialogContent style={{ overflow: 'hidden', display: 'flex', alignItems: 'end' }}>
            <TextField
              error={error}
              label='Enter Email Address'
              helperText={error ? helperText : ''}
              onChange={(event) => this.setState({ value: event.target.value })}
              onFocus={() => this.setState({ error: false })}
              fullWidth={true}
              value={this.state.value}
            />
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant='outlined'
              onClick={() => this.setState({ editOpen: false, value: '' })}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant='contained'
              onClick={this.handleEditAddress.bind(this)}
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

EmailAddressField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(EmailAddressField);
