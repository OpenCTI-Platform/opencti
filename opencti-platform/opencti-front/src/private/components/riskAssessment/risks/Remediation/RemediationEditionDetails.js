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
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import { commitMutation } from '../../../../../relay/environment';
import OpenVocabField from '../../../common/form/OpenVocabField';
import { dateFormat, parse } from '../../../../../utils/Time';
import DatePickerField from '../../../../../components/DatePickerField';
import CommitMessage from '../../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../../utils/String';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
});

// const deviceMutationFieldPatch = graphql`
//   mutation DeviceEditionDetailsFieldPatchMutation(
//     $id: ID!
//     $input: [EditInput]!
//     $commitMessage: String
//   ) {
//     threatActorEdit(id: $id) {
//       fieldPatch(input: $input, commitMessage: $commitMessage) {
//         # ...RemediationEditionDetails_remediation
//         ...Device_device
//       }
//     }
//   }
// `;

const remediationEditionDetailsFocus = graphql`
  mutation RemediationEditionDetailsFocusMutation(
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

class RemediationEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: remediationEditionDetailsFocus,
      variables: {
        id: this.props.remediation.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, classes, remediation, context, enableReferences,
    } = this.props;
    return (
      <div>
        <div style={{ height: '100%' }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Details')}
          </Typography>
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <div style={{ marginBottom: '122px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Installed Operating System')}
                  </Typography>
                  <div style={{ float: 'left', margin: '-7px 0 4px 5px' }}>
                    <Tooltip title={t('Installed Operating System')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <AddIcon fontSize="small" color="primary" />
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="installed_operating_system"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="installed_operating_system"
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
                    {t('Installed Software')}
                  </Typography>
                  <div style={{ float: 'left', margin: '13px 0 0 5px' }}>
                    <Tooltip title={t('Installed Software')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <AddIcon fontSize="small" color="primary" style={{ marginTop: 2 }} />
                  </div>
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="installed_software"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="installed_software"
                  //   />
                  // }
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 18 }}
                  >
                    {t('Motherboard ID')}
                  </Typography>
                  <div style={{ float: 'left', margin: '19px 0 0 5px' }}>
                    <Tooltip
                      title={t('Motherboard ID')}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="motherboard_id"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
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
                    <AddIcon fontSize="small" color="primary" style={{ marginTop: 2 }} />
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="ports"
                  //   />
                  // }
                  />
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="ports"
                  //   />
                  // }
                  />
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '50%' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="ports"
                  //   />
                  // }
                  />
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="ports"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '50%' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="ports"
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
                    {t('Installation ID')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Installation ID')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="installation_id"
                    size='small'
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
                    {t('Connected To Network')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Connect To Network')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    name="connected_to_network"
                    size='small'
                    variant='outlined'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
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
                    variant='outlined'
                    name="netbios_name"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
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
                    <Field
                      component={Switch}
                      name="is_virtual"
                      defaultChecked={remediation.is_virtual}
                      inputProps={{ 'aria-label': 'ant design' }}
                    />
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
                    <Field
                      component={Switch}
                      name="is_publicly_accessible"
                      defaultChecked={remediation.is_publicly_accessible}
                      inputProps={{ 'aria-label': 'ant design' }}
                    />
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
                    variant='outlined'
                    name="fqdn"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="fqdn"
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
                    {t('IPv4 Address')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('ipv4_address')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="fqdn"
                    size='small'
                    multiline={true}
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
                    {t('IPv6 Address')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('ipv6_address')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="fqdn"
                    size='small'
                    multiline={true}
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
                  <div style={{ float: 'left', margin: '-3px 0 0 5px' }}>
                    <Tooltip title={t('Installed Hardware')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <AddIcon fontSize="small" color="primary" />
                  </div>
                  <div className="clearfix" />
                  <Field
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="installed_hardware"
                    size='small'
                    fullWidth={true}
                    containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="installed_hardware"
                  //   />
                  // }
                  />
                </div>
                <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 15 }}
                >
                  {t('Location')}
                </Typography>
                <div style={{ float: 'left', margin: '16px 0 0 5px' }}>
                  <Tooltip title={t('Location')}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <Field
                  component={TextField}
                  name="Description"
                  fullWidth={true}
                  multiline={true}
                  rows="3"
                  variant='outlined'
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
                    variant='outlined'
                    name="model"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="model"
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
                    {t('MAC Address')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip
                      title={t(
                        'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                      )}
                    >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="mac_address"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="mac_addres"
                  //   />
                  // }
                  />
                </div>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left', marginTop: 19 }}
                  >
                    {t('Baseline Configuration Name')}
                  </Typography>
                  <div style={{ float: 'left', margin: '20px 0 0 5px' }}>
                    <Tooltip title={t('Baseline Configuration Name')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="baseline_configuration_name"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="baseline_configuration_name"
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
                    {t('URI')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('URI')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="uri"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="uri"
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
                    {t('BIOS ID')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('BIOS ID')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="bios_id"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="bios_id"
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
                    <Field
                      component={Switch}
                      name="is_scanned"
                      defaultChecked={remediation.is_scanned}
                      inputProps={{ 'aria-label': 'ant design' }}
                    />
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
                    variant='outlined'
                    name="hostname"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="host_name"
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
                    {t('Default Gateway')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Default Gateway')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="default_gateway"
                    size='small'
                    fullWidth={true}
                  // helperText={
                  //   <SubscriptionFocus
                  //   context={context}
                  //   fieldName="default_gateway"
                  //   />
                  // }
                  />
                </div>
              </Grid>
            </Grid>
          </Paper>
        </div>
        {/* <Grid item={true} xs={6}>
            <div style={{ display: 'grid', gridTemplateColumns: '50% 50%', marginTop: '20px' }}>
            <div style={{ marginRight: '20px' }}>
              <Form>
                <Grid style={{ marginBottom: '80px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Installed Operating System')}
                  </Typography>
                  <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                    <Tooltip title={t('Installed Operating System')} >
                      <Information fontSize="small" color="primary" />
 <Information fontSize="inherit"color="disabled" />                     </Tooltip>
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

RemediationEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

// const RemediationEditionDetails = createFragmentContainer(
//   RemediationEditionDetailsComponent,
//   {
//     remediation: graphql`
//       fragment RemediationEditionDetails_remediation on ThreatActor {
//         id
//         first_seen
//         last_seen
//         sophistication
//         resource_level
//         primary_motivation
//         secondary_motivations
//         personal_motivations
//         goals
//       }
//     `,
//   },
// );

const RemediationEditionDetails = createFragmentContainer(
  RemediationEditionDetailsComponent,
  {
    remediation: graphql`
      fragment RemediationEditionDetails_remediation on ComputingDeviceAsset {
        installed_software {
          name
        }
        connected_to_network {
          name
        }
        installed_operating_system {
          name
        }
        locations {
          city
          country
          description
        }
        uri
        model
        mac_address
        fqdn
        network_id
        baseline_configuration_name
        bios_id
        is_scanned
        hostname
        default_gateway
        motherboard_id
        installation_id
        netbios_name
        is_virtual
        is_publicly_accessible
        installed_hardware {
          name
          uri
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RemediationEditionDetails);
