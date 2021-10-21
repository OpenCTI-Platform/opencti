import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import AppBar from '@material-ui/core/AppBar';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import DeviceEditionOverview from './DeviceEditionOverview';
import DeviceEditionDetails from './DeviceEditionDetails';
import StixDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/StixDomainObjectAssetEditionOverview';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.text.primary,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const deviceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  asset_type: Yup.array().required(t('This field is required')),
  implementation_point: Yup.string().required(t('This field is required')),
  operational_status: Yup.string().required(t('This field is required')),
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

class DeviceEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    console.log('Device Edited Successfully! InputData: ', values);
    // const finalValues = pipe(
    //   assoc('createdBy', values.createdBy?.value),
    //   assoc('objectMarking', pluck('value', values.objectMarking)),
    //   assoc('objectLabel', pluck('value', values.objectLabel)),
    // )(values);
    // commitMutation({
    //   mutation: deviceCreationOverviewMutation,
    //   variables: {
    //     input: values,
    //   },
    //   // updater: (store) => insertNode(
    //   //   store,
    //   //   'Pagination_threatActors',
    //   //   this.props.paginationOptions,
    //   //   'threatActorAdd',
    //   // ),
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
    this.setState({ onSubmit: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const {
      t, classes, handleClose, device,
    } = this.props;
    console.log('DeviceEditionPropsData', device);
    const initialValues = R.pipe(
      R.assoc('id', device.id),
      R.assoc('asset_id', device.asset_id),
      R.assoc('description', device.description),
      R.assoc('name', device.name),
      R.assoc('asset_tag', device.asset_tag),
      R.assoc('asset_type', device.asset_type),
      R.assoc('location', device.locations.map((index) => [index.description]).join('\n')),
      R.assoc('version', device.version),
      R.assoc('vendor_name', device.vendor_name),
      R.assoc('serial_number', device.serial_number),
      R.assoc('release_date', device.release_date),
      R.assoc('operational_status', device.operational_status),
      R.assoc('installation_id', device.installation_id || ''),
      R.assoc('bios_id', device.bios_id || ''),
      // R.assoc('connected_to_network', device.connected_to_network.name || ''),
      R.assoc('netbios_name', device.netbios_name || ''),
      R.assoc('baseline_configuration_name', device.baseline_configuration_name || ''),
      R.assoc('mac_address', (device.mac_address || []).join()),
      R.assoc('model', device.model || ''),
      R.assoc('hostname', device.hostname || ''),
      R.assoc('default_gateway', device.default_gateway || ''),
      R.assoc('motherboard_id', device.motherboard_id || ''),
      R.assoc('is_scanned', device.is_scanned || ''),
      R.assoc('is_virtual', device.is_virtual || ''),
      R.assoc('is_publicly_accessible', device.is_publicly_accessible || ''),
      R.assoc('uri', device.uri || ''),
      R.pick([
        'id',
        'asset_id',
        'name',
        'description',
        'asset_tag',
        'asset_type',
        'location',
        'version',
        'vendor_name',
        'serial_number',
        'release_date',
        'operational_status',
        'installation_id',
        'connected_to_network',
        'bios_id',
        'netbios_name',
        'baseline_configuration_name',
        'mac_address',
        'model',
        'hostname',
        'default_gateway',
        'motherboard_id',
        'is_scanned',
        'is_virtual',
        'is_publicly_accessible',
        'uri',
      ]),
    )(device);
    const { editContext } = device;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
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
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
              >
                <Grid item={true} xs={6}>
                  {/* <DeviceEditionOverview
                device={device}
                // enableReferences={this.props.enableReferences}
                // context={editContext}
                handleClose={handleClose.bind(this)}
              /> */}
                  <StixDomainObjectAssetEditionOverview
                    stixDomainObject={device}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    handleClose={handleClose.bind(this)}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <DeviceEditionDetails
                    device={device}
                    // enableReferences={this.props.enableReferences}
                    context={editContext}
                    handleClose={handleClose.bind(this)}
                  />
                </Grid>
              </Grid>
              {/* <AppBar position="static" elevation={0} className={classes.appBar}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </AppBar>
          {this.state.currentTab === 0 && (
            <DeviceEditionOverview
              device={this.props.device}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <DeviceEditionDetails
              device={this.props.device}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )} */}
            </>
          )}
        </Formik>
      </div>
    );
  }
}

DeviceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  device: PropTypes.object,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const DeviceEditionFragment = createFragmentContainer(
  DeviceEditionContainer,
  {
    device: graphql`
      fragment DeviceEditionContainer_device on ThreatActor {
        id
        ...DeviceEditionOverview_device
        # ...DeviceEditionDetails_device
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceEditionFragment);
