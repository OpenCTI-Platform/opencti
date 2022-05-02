/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose, propOr, map } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import Edit from '@material-ui/icons/Edit';
import InputAdornment from '@material-ui/core/InputAdornment';
import Grid from '@material-ui/core/Grid';
import ApartmentOutlined from '@material-ui/icons/ApartmentOutlined';
import HomeOutlinedIcon from '@material-ui/icons/HomeOutlined';
import CallIcon from '@material-ui/icons/Call';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import TextField from '@material-ui/core/TextField';
import Button from '@material-ui/core/Button';
import Select from '@material-ui/core/Select';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
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
    width: '100%',
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

class NewAddressField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: '',
      error: false,
      ipAddress: [...this.props.addressValues],
      selectedMode: '',
    };
  }

  handleAddAddress() {
    // if (!this.props.validation.test(this.state.value)) {
    //   return this.setState({ error: true });
    // }
    if (this.state.value === '' || this.state.value === null) {
      return;
    }
    if (this.state.ipAddress.every((value) => value !== this.state.value)) {
      this.state.ipAddress.push({ 'name': this.state.value, 'type': this.state.selectedMode });
    }
    this.setState({ value: '', open: false, selectedMode: '' });
  }

  handleSubmit() {
    this.setState({ open: false, value: '' }, () => (
      this.props.setFieldValue(this.props.name, this.state.ipAddress)
    ));
  }
  handleChangeMode(event) {
    this.setState({ selectedMode: event.target.value });
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((value, i) => i !== key) });
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
              {this.state.ipAddress.map((address, key) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    {address.type === 'office'
                      ? <ApartmentOutlined />
                      : address.type === 'mobile'
                        ? <HomeOutlinedIcon />
                        : <CallIcon />}
                    <Typography>
                      {address.name}
                    </Typography>
                  </div>
                  <div style={{ display: 'flex' }}>
                    <IconButton
                    // onClick={this.handleEditionAddress.bind(this, key)}
                    >
                      <Edit />
                    </IconButton>
                    <IconButton onClick={this.handleDeleteAddress.bind(this, key)}>
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
          <DialogContent>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <FormControl
                  size='small'
                  fullWidth={true}
                  className={classes.dataEntities}
                >
                  <InputLabel>
                    Usage Type
                  </InputLabel>
                  <Select
                    value={this.state.selectedMode}
                    onChange={this.handleChangeMode.bind(this)}
                    className={classes.dataSelect}
                  >
                    <MenuItem value='office'><ApartmentOutlined />Office</MenuItem>
                    <MenuItem value='mobile'><HomeOutlinedIcon />Mobile</MenuItem>
                    <MenuItem value='home'><CallIcon />Home</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item={true} xs={6}>
                <TextField
                  error={error}
                  helperText={error ? helperText : ''}
                  onChange={(event) => this.setState({ value: event.target.value })}
                  onFocus={() => this.setState({ error: false })}
                  fullWidth={true}
                  value={this.state.value}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <TextField
                  error={error}
                  helperText={error ? helperText : ''}
                  onChange={(event) => this.setState({ value: event.target.value })}
                  onFocus={() => this.setState({ error: false })}
                  fullWidth={true}
                  value={this.state.value}
                />
              </Grid>
            </Grid>
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
      </>
    );
  }
}

NewAddressField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(NewAddressField);
