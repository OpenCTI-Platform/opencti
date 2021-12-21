/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose, evolve } from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Drawer from '@material-ui/core/Drawer';
import Fab from '@material-ui/core/Fab';
import {
  Add,
  Edit,
  Close,
  Delete,
  ArrowBack,
  AddCircleOutline,
  CheckCircleOutline,
} from '@material-ui/icons';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { dayStartDate, parse } from '../../../../utils/Time';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DeviceCreationOverview from './DeviceCreationOverview';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetCreationOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetCreationOverview';
import CyioCoreObjectAssetCreationExternalReferences from '../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import Loader from '../../../../components/Loader';
import DeviceCreationDetails from './DeviceCreationDetails';

const styles = (theme) => ({
  container: {
    marginBottom: 0,
  },
  header: {
    margin: '-25px -24px 20px -24px',
    padding: '23px 24px 24px 24px',
    height: '64px',
    backgroundColor: theme.palette.background.paper,
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '8px 16px 8px 8px',
  },
  title: {
    float: 'left',
  },
  rightContainer: {
    float: 'right',
    marginTop: '-10px',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

const deviceCreationMutation = graphql`
  mutation DeviceCreationMutation($input: ComputingDeviceAssetAddInput) {
    createComputingDeviceAsset (input: $input) {
      id
      # ...DeviceCard_node
      # ...DeviceDetails_device
      # operational_status
      # serial_number
      # release_date
      # description
      # version
      # name
    }
  }
`;

const deviceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  port_number: Yup.number().required(t('This field is required')),
  portocols: Yup.string(),
  asset_type: Yup.string().required(t('This field is required')),
});

class DeviceCreation extends Component {
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
    const ports = {
      "port_number": values.port_number,
      "protocols": values.protocols || 'TCP',
    }
    const adaptedValues = evolve(
      {
        release_date: () => parse(values.release_date).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.dissoc('port_number'),
      R.dissoc('installed_operating_system'),
      R.dissoc('installed_hardware'),
      R.dissoc('installed_software'),
      R.dissoc('locations'),
      R.dissoc('connected_to_network'),
      R.dissoc('protocols'),
      R.assoc('name', values.name),
      R.assoc('asset_type', values.asset_type),
      R.assoc('ports', ports),
    )(adaptedValues);
    CM(environmentDarkLight, {
      mutation: deviceCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/dashboard/assets/devices');
      },
    });
    // commitMutation({
    //   mutation: deviceCreationMutation,
    //   variables: {
    //     input: values,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_computingDeviceAssetList',
    //     this.props.paginationOptions,
    //     'createComputingDeviceAsset',
    //   ),
    //   setSubmitting,
    //   onCompleted: (data) => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
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
      t,
      classes,
      deviceId,
      open,
      history,
    } = this.props;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            name: 'Hello World',
            operational_status: 'other',
            // id: '',
            asset_id: '',
            asset_tag: '',
            description: '',
            version: '',
            serial_number: '',
            vendor_name: '',
            release_date: dayStartDate(),
            ipv4_address: [],
            locations: [],
            ipv6_address: [],
            protocols: '',
            port_number: '',
            model: '',
            uri: null,
            installation_id: '',
            motherboard_id: '',
            connected_to_network: '',
            netbios_name: '',
            is_virtual: false,
            is_publicly_accessible: false,
            is_scanned: false,
            baseline_configuration_name: '',
            bios_id: '',
            hostname: '',
            default_gateway: '',
            labels: [],
            asset_type: 'physical_device',
            mac_address: [],
            installed_operating_system: [],
            installed_hardware: [],
            installed_software: [],
            fqdn: '',
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
              <div className={classes.header}>
                <Typography
                  variant="h1"
                  gutterBottom={true}
                  classes={{ root: classes.title }}
                >
                  {t('New Asset')}
                </Typography>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      onClick={() => history.goBack()}
                      className={classes.iconButton}
                    >
                      {t('Cancel')}
                    </Button>
                  </Tooltip>
                  <Tooltip title={t('Create')}>
                    <Button
                      variant="contained"
                      color="primary"
                      startIcon={<CheckCircleOutline />}
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.iconButton }}
                    >
                      {t('Done')}
                    </Button>
                  </Tooltip>
                </div>
              </div>
              <Form>
                <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                >
                  <Grid item={true} xs={6}>
                    {/* <DeviceCreationOverview setFieldValue={setFieldValue} values={values} /> */}
                    <CyioDomainObjectAssetCreationOverview
                      setFieldValue={setFieldValue}
                      values={values}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <DeviceCreationDetails setFieldValue={setFieldValue} />
                  </Grid>
                </Grid>
              </Form>
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 25 }}
              >
                <Grid item={true} xs={6}>
                  {/* <StixCoreObjectExternalReferences
                      stixCoreObjectId={device.id}
                    /> */}
                  <CyioCoreObjectAssetCreationExternalReferences />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes />
            </>
          )}
        </Formik>
      </div>
    );
  }
}

DeviceCreation.propTypes = {
  deviceId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceCreation);
