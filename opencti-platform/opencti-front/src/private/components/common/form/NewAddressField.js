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
import Button from '@material-ui/core/Button';
import Select from '@material-ui/core/Select';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@material-ui/core';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
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
    console.log(this);
    // if (!this.props.validation.test(this.state.value)) {
    //   return this.setState({ error: true });
    // }
    // if (this.state.value === '' || this.state.value === null) {
    //   return;
    // }
    // if (this.state.ipAddress.every((value) => value !== this.state.value)) {
    //   this.state.ipAddress.push({ 'name': this.state.value, 'type': this.state.selectedMode });
    // }
    // this.setState({ value: '', open: false, selectedMode: '' });
  }

  // handleSubmit() {
  //   this.setState({ open: false, value: '' }, () => (
  //     this.props.setFieldValue(this.props.name, this.state.ipAddress)
  //   ));
  // }

  handleChangeMode(event) {
    this.setState({ selectedMode: event.target.value });
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((value, i) => i !== key) });
  }

  render() {
    const {
      t,
      fldt,
      classes,
      name,
      title,
      helperText,
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
          <Formik
            enableReinitialize={true}
            initialValues={{
              usage_type: '',
              city: '',
              street_address: '',
              administrative_area: '',
              country: '',
              postal_code: '',
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.handleAddAddress.bind(this)}
          // onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle>
                  {t(`Add or Edit ${title}`)}
                </DialogTitle>
                <DialogContent>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Field
                        component={SelectField}
                        name="usage_type"
                        label='Usage Type'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      >
                        <MenuItem value='office'><ApartmentOutlined />Office</MenuItem>
                        <MenuItem value='mobile'><HomeOutlinedIcon />Mobile</MenuItem>
                        <MenuItem value='home'><CallIcon />Home</MenuItem>
                      </Field>
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Street Address')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Street Address')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="street_address"
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('City')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('City')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="city"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Country')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Country')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="country"
                          variant='outlined'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Administrative Area')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Administrative Area')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="administrative_area"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Postal Code')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Postal Code')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="postal_code"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
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
                    onClick={submitForm}
                    color="primary"
                  >
                    {t('Submit')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
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
