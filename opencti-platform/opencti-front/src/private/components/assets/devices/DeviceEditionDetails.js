/* eslint-disable */
/* refactor */
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
import SwitchField from '../../../../components/SwitchField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import OpenVocabField from '../../common/form/OpenVocabField';
import { dateFormat, parse } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import InstalledAsset from '../../common/form/InstalledAsset';
import ItemIcon from '../../../../components/ItemIcon';
import Protocols from '../../common/form/Protocols';

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
//         # ...DeviceEditionDetails_device
//         ...Device_device
//       }
//     }
//   }
// `;

const deviceEditionDetailsFocus = graphql`
  mutation DeviceEditionDetailsFocusMutation(
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

class DeviceEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: deviceEditionDetailsFocus,
      variables: {
        id: this.props.device?.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, classes, device, enableReferences,
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
                  <InstalledAsset
                    component={SelectField}
                    variant='outlined'
                    type='software'
                    assetType="operating-system"
                    name="installed_operating_system"
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
                    {t('Installed Software')}
                  </Typography>
                  <div style={{ float: 'left', margin: '13px 0 0 5px' }}>
                    <Tooltip title={t('Installed Software')} >
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                    <AddIcon fontSize="small" color="primary" style={{ marginTop: 2 }} />
                  </div>
                  <InstalledAsset
                    component={SelectField}
                    variant='outlined'
                    type='software'
                    multiple={true}
                    name="installed_software"
                    // disabled={true}
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
                    component={TextField}
                    style={{  width: '50%' }}
                    type="number"
                    variant='outlined'
                    name="port_number"
                    size='small'
                    fullWidth={true}
                  />
                  <Protocols
                    component={SelectField}
                    style={{ height: '38.09px' }}
                    variant='outlined'
                    name="protocols"
                    size='small'
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
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    name="connected_to_network"
                    size='small'
                    variant='outlined'
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
                    name="ipv4_address"
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
                    name="ipv6_address"
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
                  <InstalledAsset
                    component={SelectField}
                    variant='outlined'
                    type='hardware'
                    multiple={true}
                    name="installed_hardware"
                    // disabled={true}
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
              </Grid>
            </Grid>
          </Paper>
        </div>
      </div>
    );
  }
}

DeviceEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  device: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const DeviceEditionDetails = createFragmentContainer(
  DeviceEditionDetailsComponent,
  {
    device: graphql`
      fragment DeviceEditionDetails_device on ComputingDeviceAsset {
        installed_software {
          name
        }
        connected_to_network {
          name
        }
        installed_operating_system {
          id
          name
          vendor_name
        }
        locations {
          city
          country
          description
        }
        ipv4_address {
          ip_address_value
        }
        ipv6_address {
          ip_address_value
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
)(DeviceEditionDetails);
