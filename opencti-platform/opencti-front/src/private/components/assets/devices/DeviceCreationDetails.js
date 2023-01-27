import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import SwitchField from '../../../../components/SwitchField';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { commitMutation } from '../../../../relay/environment';
import InstalledAsset from '../../common/form/InstalledAsset';
import PortsField from '../../common/form/PortsField';
import AddressField from '../../common/form/AddressField';
import { ipv4AddrRegex, ipv6AddrRegex, macAddrRegex } from '../../../../utils/Network';
import TaskType from '../../common/form/TaskType';

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
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
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

  render() {
    const {
      t,
      classes,
      values,
      isSubmitting,
      setFieldValue,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <div style={{ marginBottom: '45px' }}>
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
                </div>
                <InstalledAsset
                  component={SelectField}
                  variant='outlined'
                  type='software'
                  assetType="operating-system"
                  name="installed_operating_system"
                  fullWidth={true}
                  style={{ height: '38.09px', maxWidth: '300px' }}
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
                  {t('Installed Software')}
                </Typography>
                <div style={{ float: 'left', margin: '15px 0 0 5px' }}>
                  <Tooltip title={t('Installed Software')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <InstalledAsset
                  component={SelectField}
                  variant='outlined'
                  type='software'
                  multiple={true}
                  name="installed_software"
                  // disabled={true}
                  fullWidth={true}
                  style={{ height: '38.09px', maxWidth: '300px' }}
                  containerstyle={{ width: '100%' }}
                  helperText={t('Select device')}
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
                  variant='outlined'
                  name="motherboard_id"
                  size='small'
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
                  size='small'
                  variant='outlined'
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
                  variant='outlined'
                  name="netbios_name"
                  size='small'
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
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="is_virtual"
                    containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
                    inputProps={{ 'aria-label': 'ant design' }}
                  />
                  <Typography>Yes</Typography>
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
                      component={SwitchField}
                      type="checkbox"
                      name="is_scanned"
                      containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
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
                  />
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
                />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Implementation Point')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Implementation Point')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <TaskType
                  name="implementation_point"
                  taskType='ImplementationPoint'
                  fullWidth={true}
                  style={{ height: '38.09px' }}
                  containerstyle={{ width: '100%' }}
                  variant='outlined'
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
                </div>
                <div className="clearfix" />
                <InstalledAsset
                  component={SelectField}
                  variant='outlined'
                  type='hardware'
                  multiple={true}
                  name="installed_hardware"
                  // disabled={true}
                  fullWidth={true}
                  style={{ height: '38.09px', maxWidth: '300px' }}
                  containerstyle={{ width: '100%' }}
                  helperText={t('Select device')}
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
                  name="locations"
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
                  variant='outlined'
                  name="baseline_configuration_name"
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
                />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('Publicly Accessible')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Publicly Accessible')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography>No</Typography>
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="is_publicly_accessible"
                    containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
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
                  {t('Last Scanned')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('Last Scanned')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={DateTimePickerField}
                  variant="outlined"
                  name="last_scanned"
                  size="small"
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD HH:MM)',
                  )}
                  fullWidth={true}
                  style={{ height: '38.09px' }}
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
                />
              </div>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: 'left', marginTop: 20 }}
                >
                  {t('CPE Identifier')}
                </Typography>
                <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                  <Tooltip title={t('CPE Identifier')} >
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <Field
                  component={TextField}
                  variant='outlined'
                  name="cpe_identifier"
                  size='small'
                  fullWidth={true}
                />
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <PortsField
                setFieldValue={setFieldValue}
                disabled={isSubmitting}
                values={values}
                variant='outlined'
                title='Port'
                name="ports"
                fullWidth={true}
                containerstyle={{ width: '100%' }}
              />
            </Grid>
            <Grid item={true} xs={12}>
              <AddressField
                setFieldValue={setFieldValue}
                values={values}
                addressValues={values.mac_address}
                title='Mac Address'
                name='mac_address'
                validation={macAddrRegex}
                helperText='Please enter a valid MAC Address. Example: 78:B0:92:0D:EF:1C'
              />
            </Grid>
            <Grid item={true} xs={12}>
              <AddressField
                setFieldValue={setFieldValue}
                values={values}
                addressValues={values.ipv4_address}
                title='IPv4 Address'
                name='ipv4_address'
                validation={ipv4AddrRegex}
                helperText='​Please enter a valid iPv4 Address. Example: 69.204.156.182'
              />
            </Grid>
            <Grid item={true} xs={12}>
              <AddressField
                setFieldValue={setFieldValue}
                values={values}
                addressValues={values.ipv6_address}
                title='IPv6 Address'
                name='ipv6_address'
                validation={ipv6AddrRegex}
                helperText='Please enter a valid iPv6 Address. Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334'
              />
            </Grid>
          </Grid>
        </Paper>
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
