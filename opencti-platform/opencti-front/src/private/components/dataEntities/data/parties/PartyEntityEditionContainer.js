/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import NoteAddIcon from '@material-ui/icons/NoteAdd';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import { FormControlLabel } from '@material-ui/core';
import Radio from '@material-ui/core/Radio';
import RadioGroup from '@material-ui/core/RadioGroup';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import AddIcon from '@material-ui/icons/Add';
import { MoreVertOutlined } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import { dateFormat, parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import SelectField from '../../../../../components/SelectField';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from '../../../../../utils/bakedToast';
import DataAddressField from '../../../common/form/DataAddressField';
import NewAddressField from '../../../common/form/NewAddressField';
import LocationField from '../../../common/form/LocationField';
import { ipv6AddrRegex, telephoneFormatRegex, emailAddressRegex } from '../../../../../utils/Network';

const styles = (theme) => ({
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'scroll',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  radioButtonGroup: {
    '&.MuiFormGroup-root': {
      display: 'block',
    },
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const partyEntityEditionContainerMutation = graphql`
  mutation PartyEntityEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editOscalParty(id: $id, input: $input) {
      id
    }
  }
`;

class PartyEntityEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      details: false,
      close: false,
      onSubmit: false,
      radioButtonValue: 'locations',
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleSubmit() {
    this.setState({ onSumbit: true });
  }

  handleChangeRadioButton(event) {
    this.setState({ radioButtonValue: event.target.value });
  }

  onReset() {
    this.handleClose();
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.evolve(
      {
        modified: () => values.modified === null ? null : parse(values.modified).format(),
        created: () => values.created === null ? null : parse(values.created).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    CM(environmentDarkLight, {
      mutation: partyEntityEditionContainerMutation,
      variables: {
        id: this.props.party.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
      onError: (err) => {
        console.error(err);
        return toastGenericError('Request Failed');
      }
    });
    this.setState({ onSubmit: true });
  }

  render() {
    const {
      classes,
      t,
      disabled,
      party,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', party?.name || ''),
      R.assoc('description', party?.description || ''),
      R.assoc('telephone_numbers', []),
      R.assoc('email_address', []),
      R.assoc('address', []),
      R.assoc('locations', []),
      R.assoc('created', null),
      R.assoc('modified', null),
      R.assoc('short_name', ''),
      R.assoc('party_type', ''),
      R.pick([
        'name',
        'created',
        'modified',
        'short_name',
        'party_type',
        'member_of',
        'mail_stop',
        'job_title',
        'office',
        'marking',
        'description',
        'address',
        'locations',
        'email_address',
        'telephone_numbers',
        'external_identifiers',
      ]),
    )(party);
    return (
      <>
        <Dialog
          open={this.props.displayEdit}
          keepMounted={true}
          onClose={() => this.props.handleDisplayEdit()}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
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
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Party')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Id')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Id')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="id"
                          disabled={true}
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Created Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Created')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="created"
                          fullWidth={true}
                          disabled={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                        />
                      </div>
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="name"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
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
                          {t('Modified Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Last Modified')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="modified"
                          fullWidth={true}
                          disabled={true}
                          size="small"
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Short Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Short Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="short_name"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Description')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name='description'
                        fullWidth={true}
                        multiline={true}
                        rows='3'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Party Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Short Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="party_type"
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Member Of')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Member Of')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="member_of"
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Mail Stop')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Mail Stop')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="mail_stop"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <DataAddressField
                          setFieldValue={setFieldValue}
                          values={values}
                          addressValues={values.telephone_numbers}
                          title='Telephone numbers'
                          name='telephone_numbers'
                          validation={telephoneFormatRegex}
                          helperText='Please enter a valid Telephone Number. Example: +1 999 999-9999'
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Job Title')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Job Title')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="job_title"
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('External Identifiers')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('External Identifiers')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="external_identifiers"
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
                          {t('Office')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Office')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="office"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                      <div style={{ marginTop: '10px' }}>
                        <DataAddressField
                          setFieldValue={setFieldValue}
                          values={values}
                          addressValues={values.email_address}
                          title='Email Address'
                          name='email_address'
                          validation={emailAddressRegex}
                          helperText='Please enter a valid Email Address. Example: support@darklight.ai'
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <RadioGroup
                        aria-labelledby="demo-controlled-radio-buttons-group"
                        name="controlled-radio-buttons-group"
                        className={classes.radioButtonGroup}
                        value={this.state.radioButtonValue}
                        onChange={this.handleChangeRadioButton.bind(this)}
                      >
                        <FormControlLabel value="locations" control={<Radio />} label="Locations" />
                        <FormControlLabel value="address" control={<Radio />} label="Address" />
                      </RadioGroup>
                    </Grid>
                    <Grid item={true} xs={12}>
                      {this.state.radioButtonValue === 'address' ? (
                        <NewAddressField
                          setFieldValue={setFieldValue}
                          values={values}
                          addressValues={values.address}
                          title='Address(es)'
                          name='address'
                          // validation={emailAddressRegex}
                          helperText='Please enter a valid Email Address. Example: support@darklight.ai'
                        />
                      ) : (
                        <LocationField
                          setFieldValue={setFieldValue}
                          values={values}
                          addressValues={values.locations}
                          title='Location(s)'
                          name='locations'
                          helperText='Please enter a valid MAC Address. Example: 78:B0:92:0D:EF:1C'
                        />
                      )}
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Marking')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Marking')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="marking"
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    // onClick={handleReset}
                    onClick={() => this.props.handleDisplayEdit()}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
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

PartyEntityEditionContainer.propTypes = {
  handleDisplayEdit: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  party: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
  enableReferences: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(PartyEntityEditionContainer);
