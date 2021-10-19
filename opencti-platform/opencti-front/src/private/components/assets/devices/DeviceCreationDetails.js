import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Switch from '@material-ui/core/Switch';
import Paper from '@material-ui/core/Paper';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import AddIcon from '@material-ui/icons/Add';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import OpenVocabField from '../../common/form/OpenVocabField';
import { dateFormat, parse } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import Ports from '../../common/form/Ports';
import Protocols from '../../common/form/Protocols';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

const deviceMutationFieldPatch = graphql`
  mutation DeviceCreationDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...DeviceCreationDetails_device
        ...Device_device
      }
    }
  }
`;

const deviceCreationDetailsFocus = graphql`
  mutation DeviceCreationDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const deviceValidation = (t) => Yup.object().shape({
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  last_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  sophistication: Yup.string().nullable(),
  resource_level: Yup.string().nullable(),
  primary_motivation: Yup.string().nullable(),
  secondary_motivations: Yup.array().nullable(),
  personal_motivations: Yup.array().nullable(),
  goals: Yup.string().nullable(),
});

class DeviceCreationDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: deviceCreationDetailsFocus,
      variables: {
        id: this.props.device.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.assoc(
        'goals',
        values.goals && values.goals.length ? R.split('\n', values.goals) : [],
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: deviceMutationFieldPatch,
      variables: {
        id: this.props.device.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
      },
      onCompleted: () => {
        setSubmitting(false);
        // this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'goals') {
        finalValue = R.split('\n', value);
      }
      deviceValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: deviceMutationFieldPatch,
            variables: {
              id: this.props.device.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const {
      t, classes, device, context, enableReferences,
    } = this.props;
    // const initialValues = R.pipe(
    //   R.assoc('first_seen', dateFormat(device.first_seen)),
    //   R.assoc('last_seen', dateFormat(device.last_seen)),
    //   R.assoc(
    //     'secondary_motivations',
    //     device.secondary_motivations
    //       ? device.secondary_motivations
    //       : [],
    //   ),
    //   R.assoc(
    //     'personal_motivations',
    //     device.personal_motivations ? device.personal_motivations : [],
    //   ),
    //   R.assoc(
    //     'goals',
    //     R.join('\n', device.goals ? device.goals : []),
    //   ),
    //   R.pick([
    //     'first_seen',
    //     'last_seen',
    //     'sophistication',
    //     'resource_level',
    //     'primary_motivation',
    //     'secondary_motivations',
    //     'personal_motivations',
    //     'goals',
    //   ]),
    // )(device);
    return (
      <div>
        <Formik
          initialValues={{
            installed_operating_system: '',
            motherboard_id: '',
            ports: [],
            asset_type: [],
            installation_id: '',
            description: '',
            connected_to_network: {},
            bios_id: '',
            is_virtual: false,
            is_publicly_accessible: false,
            fqdn: '',
            installed_hardware: {},
            model: '',
            mac_address: '',
            baseline_configuration_name: '',
            uri: '',
            is_scanned: false,
            hostname: '',
            default_gateway: '',
          }}
          validationSchema={deviceValidation(t)}
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
            <>
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Details')}
              </Typography>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <Form>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '119px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Installed Operating System')}
                        </Typography>
                        <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                          <Tooltip title={t('Installed Operating System')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon fontSize="small" color="disabled" />
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="installed_operating_system"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Installed Software')}
                        </Typography>
                        <div style={{ float: 'left', margin: '15px 0 0 5px' }}>
                          <Tooltip title={t('Installed Software')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon fontSize="small" color="disabled" style={{ marginTop: 2 }} />
                        </div>
                        <Field
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="installed_software"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Motherboard ID')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip
                            title={t('Motherboard ID')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="motherboard_id"
                          size= 'small'
                          fullWidth={true}
                          // helperText={
                          //   <SubscriptionFocus
                          //   fieldName="motherboard_id"
                          //   />
                          // }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Ports')}
                        </Typography>
                        <div style={{ float: 'left', margin: '12px 0 0 5px' }}>
                          <Tooltip title={t('Ports')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon fontSize="small" color="disabled" style={{ marginTop: 2 }} />
                        </div>
                        <div className="clearfix" />
                        <Ports
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="ports"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                        />
                        <Protocols
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="protocols"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Installation ID')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Installation ID')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="installation_id"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Connect To Network')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Connect To Network')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          name="connected_to_network"
                          size= 'small'
                          variant= 'outlined'
                          fullWidth={true}
                          // helperText={
                          //   <SubscriptionFocus
                          //   fieldName="connect_to_network"
                          //   />
                          // }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('NetBIOS Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('NetBIOS Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="bios_id"
                          size= 'small'
                          fullWidth={true}
                          // helperText={
                          //   <SubscriptionFocus
                          //   fieldName="netbios_name"
                          //   />
                          // }
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Virtual')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Virtual')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                            <Typography>No</Typography>
                            <Switch defaultChecked inputProps={{ 'aria-label': 'ant design' }} />
                            <Typography>Yes</Typography>
                        </div>
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Publicity Accessible')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Publicity Accessible')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                            <Typography>No</Typography>
                            <Switch defaultChecked inputProps={{ 'aria-label': 'ant design' }} />
                            <Typography>Yes</Typography>
                        </div>
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('FQDN')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Outlined')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="fqdn"
                          size= 'small'
                          fullWidth={true}
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
                          {t('Installed Hardware')}
                        </Typography>
                        <div style={{ float: 'left', margin: '-5px 0 0 5px' }}>
                          <Tooltip title={t('Installed Hardware')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon fontSize="small" color="disabled" />
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="installed_hardware"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                        <Field
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="installed_hardware"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                        <Field
                          component={SelectField}
                          style={{ height: '38.09px' }}
                          variant= 'outlined'
                          name="installed_hardware"
                          size= 'small'
                          fullWidth={true}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Description')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="description"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Model')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Model')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="model"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('MAC Address')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('MAC Address')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="mac_address"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Baseline Configuration Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Baseline Configuration Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="baseline_configuration_name"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('URI')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('URI')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="uri"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('BIOS ID')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('BIOS ID')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="bios_id"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Scanned')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Scanned')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                            <Typography>No</Typography>
                            <Switch defaultChecked inputProps={{ 'aria-label': 'ant design' }} />
                            <Typography>Yes</Typography>
                        </div>
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Host Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Host Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="hostname"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                      <div>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left', marginTop: 20 }}
                        >
                          {t('Default Gateway')}
                        </Typography>
                        <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                          <Tooltip title={t('Default Gateway')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <Field
                          component={TextField}
                          variant= 'outlined'
                          name="default_gateway"
                          size= 'small'
                          fullWidth={true}
                        />
                      </div>
                    </Grid>
                  </Grid>
                </Form>
              </Paper>
            </div>
            {/* <Grid item={true} xs={6}>
            <div style={{ display: 'grid', gridTemplateColumns: '50% 50%', marginTop: '20px' }}>
            <div style={{ marginRight: '20px' }}>
              <Form>
                <Grid style={{ marginBottom: '80px' }}>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Installed Operating System')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Installed Operating System')} >
                      <Information fontSize="small" color="primary" />
                    </Tooltip>
                    <AddIcon fontSize="small" color="primary" />
                  </div>
                  <Field
                    component={TextField}
                    variant= 'outlined'
                    name="installed_operating_system"
                    label={t('Installed Operating System')}
                    size= 'small'
                    fullWidth={true}
                    helperText={
                      <SubscriptionFocus
                      context={context}
                      fieldName="installed_operating_system"
                      />
                    }
                  />
                </Grid>
                <Grid style={{ marginBottom: '15px' }}>
                </Grid>
                <Grid style={{ marginBottom: '15px' }}>
                </Grid>
                  <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                  <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
              </Form>
            </div>
            <div>
            <Form>
            <Grid style={{ marginBottom: '15px' }}>
            </Grid>
                      <Grid style={{ marginBottom: '15px' }}>
                    </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
                      <Grid style={{ marginBottom: '15px' }}>
                    </Grid>
                    <Grid style={{ marginBottom: '15px' }}>
                  </Grid>
              </Form>
            </div>
            </div> */}
           </>
        )}
        </Formik>
        {/* <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={deviceValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
        >
          {({ submitForm, isSubmitting, validateForm }) => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={DatePickerField}
                  name="first_seen"
                  label={t('First seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="first_seen"
                    />
                  }
                />
                <Field
                  component={DatePickerField}
                  name="last_seen"
                  label={t('Last seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="last_seen"
                    />
                  }
                />
                <Field
                  component={SelectField}
                  style={{ height: '38.09px' }}
                  name="sophistication"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Sophistication')}
                  fullWidth={true}
                  containerstyle={{ width: '100%', marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="sophistication"
                    />
                  }
                >
                  <MenuItem key="none" value="none">
                    {t('sophistication_none')}
                  </MenuItem>
                  <MenuItem key="minimal" value="minimal">
                    {t('sophistication_minimal')}
                  </MenuItem>
                  <MenuItem key="intermediate" value="intermediate">
                    {t('sophistication_intermediate')}
                  </MenuItem>
                  <MenuItem key="advanced" value="advanced">
                    {t('sophistication_advanced')}
                  </MenuItem>
                  <MenuItem key="expert" value="expert">
                    {t('sophistication_expert')}
                  </MenuItem>
                  <MenuItem key="innovator" value="innovator">
                    {t('sophistication_innovator')}
                  </MenuItem>
                  <MenuItem key="strategic" value="strategic">
                    {t('sophistication_strategic')}
                  </MenuItem>
                </Field>
                <OpenVocabField
                  label={t('Resource level')}
                  type="attack-resource-level-ov"
                  name="resource_level"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Primary motivation')}
                  type="attack-motivation-ov"
                  name="primary_motivation"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Secondary motivations')}
                  type="attack-motivation-ov"
                  name="secondary_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Personal motivations')}
                  type="attack-motivation-ov"
                  name="personal_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <Field
                  component={TextField}
                  name="goals"
                  label={t('Goals (1 / line)')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus context={context} fieldName="goals" />
                  }
                />
                {enableReferences && (
                  <CommitMessage
                    submitForm={submitForm}
                    disabled={isSubmitting}
                    validateForm={validateForm}
                  />
                )}
              </Form>
            </div>
          )}
        </Formik> */}
      </div>
    );
  }
}

DeviceCreationDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  device: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const DeviceCreationDetails = createFragmentContainer(
  DeviceCreationDetailsComponent,
  {
    device: graphql`
      fragment DeviceCreationDetails_device on ThreatActor {
        id
        first_seen
        last_seen
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        personal_motivations
        goals
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceCreationDetails);
