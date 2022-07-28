/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose, propOr, map } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import * as Yup from 'yup';
import Edit from '@material-ui/icons/Edit';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
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
import TaskType from '../../common/form/TaskType';
import ItemIcon from '../../../../components/ItemIcon';

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

const NewAddressFieldValidation = (t) => Yup.object().shape({
  address_type: Yup.string().required(t('This field is required')),
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

  handleSubmit(values, { setSubmitting, resetForm }) {
    this.state.ipAddress.push(values);
    this.setState({ open: false }, () => (
      this.props.setFieldValue(this.props.name, this.state.ipAddress)
    ));
  }

  handleChangeMode(event) {
    this.setState({ selectedMode: event.target.value });
  }

  handleDeleteAddress(key) {
    this.setState({ ipAddress: this.state.ipAddress.filter((value, i) => i !== key) }, () => (
      this.props.setFieldValue(this.props.name, this.state.ipAddress)
    ));
  }

  onReset() {
    this.setState({ open: false });
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
          <IconButton disabled={this.state.ipAddress.length > 0} size='small' onClick={() => this.setState({ open: true })}>
            <AddIcon />
          </IconButton>
        </div>
        <div className={classes.scrollBg}>
          <div className={classes.scrollDiv}>
            <div className={classes.scrollObj}>
              {this.state.ipAddress.map((address, key) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <ItemIcon type={address.address_type} />
                    <Typography>
                      {t(`${address.street_address}, ${address.city}, ${address.administrative_area}, ${address.postal_code} ${address.country_code}`)}
                    </Typography>
                  </div>
                  <div style={{ display: 'flex' }}>
                    <IconButton
                      size='small'
                    // onClick={this.handleEditionAddress.bind(this, key)}
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
          onClose={this.onReset.bind(this)}
          fullWidth={true}
          maxWidth='sm'
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              address_type: '',
              city: '',
              street_address: '',
              administrative_area: '',
              country_code: '',
              postal_code: '',
            }}
            validationSchema={NewAddressFieldValidation(t)}
            onSubmit={this.handleSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
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
                        name="address_type"
                        label='Address Type'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      >
                        <MenuItem value='office'><ItemIcon type='office' />Office</MenuItem>
                        <MenuItem value='mobile'><ItemIcon type='mobile' />Mobile</MenuItem>
                        <MenuItem value='home'><ItemIcon type='home' />Home</MenuItem>
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
                        <TaskType
                          name='country_code'
                          taskType='Iso3166CountryCode'
                          fullWidth={true}
                          variant='outlined'
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
                    onClick={handleReset}
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
