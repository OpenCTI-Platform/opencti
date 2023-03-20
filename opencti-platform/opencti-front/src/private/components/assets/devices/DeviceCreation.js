/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose, evolve } from 'ramda';
import { Formik, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import {
  Close
} from '@material-ui/icons';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Slide from '@material-ui/core/Slide';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import graphql from 'babel-plugin-relay/macro';
import { parse } from '../../../../utils/Time';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetCreationOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetCreationOverview';
import CyioCoreObjectAssetCreationExternalReferences from '../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import { toastGenericError } from "../../../../utils/bakedToast";
import DeviceCreationDetails from './DeviceCreationDetails';

const styles = (theme) => ({
  container: {
    marginBottom: 0,
  },
  header: {
    display: 'flex',
    height: '70px',
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1rem 1.5rem',
    justifyContent: 'space-between',
    backgroundColor: theme.palette.background.paper,
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
  },
  title: {
    float: 'left',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  rightContainer: {
    display: 'flex',
    alignItems: 'center',
  },
  leftContainer: {
    display: 'flex',
    alignItems: 'center',
    marginTop: '0.5rem',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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
  mutation DeviceCreationMutation($input: HardwareAssetAddInput) {
    createHardwareAsset (input: $input) {
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
  port_number: Yup.number().moreThan(0, 'The port number must be greater than 0'),
  uri: Yup.string().nullable().url('The value must be a valid URL (scheme://host:port/path). For example, https://cyio.darklight.ai'),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class DeviceCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
        ipv4_address: () => values.ipv4_address.length > 0 ? values.ipv4_address.map((address) => { return { ip_address_value: address } }) : [],
        ipv6_address: () => values.ipv6_address.length > 0 ? values.ipv6_address.map((address) => { return { ip_address_value: address } }) : [],
      },
      values,
    );
    const finalValues = R.pipe(
      R.dissoc('labels'),
      R.dissoc('locations'),
      R.dissoc('protocols'),
      R.dissoc('port_number'),
      R.assoc('asset_type', values.asset_type),
    )(adaptedValues);
    commitMutation({
      mutation: deviceCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/defender_hq/assets/devices');
      },
      pathname: '/defender_hq/assets/devices',
      onError: () => {
        toastGenericError("Failed to create Device");
      }
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

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const {
      t,
      classes,
    } = this.props;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            name: '',
            operational_status: 'other',
            // id: '',
            asset_id: '',
            asset_tag: '',
            description: '',
            version: '',
            serial_number: '',
            vendor_name: '',
            cpe_identifier: '',
            release_date: null,
            ipv4_address: [],
            locations: [],
            ipv6_address: [],
            ports: [],
            protocols: [],
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
            last_scanned: null,
            baseline_configuration_name: '',
            bios_id: '',
            hostname: '',
            default_gateway: '',
            labels: [],
            asset_type: 'computing_device',
            mac_address: [],
            installed_operating_system: '',
            installed_hardware: [],
            installed_software: [],
            fqdn: '',
            implementation_point: 'internal',
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
                  className={ classes.leftContainer }
                >
                  {t('New Asset')}
                </Typography>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      startIcon={<Close />}
                      onClick={this.handleOpenCancelButton.bind(this)}
                      className={classes.iconButton}
                    >
                      {t('Cancel')}
                    </Button>
                  </Tooltip>
                  <Tooltip title={t('Create')}>
                    <Button
                      variant="contained"
                      color="primary"
                      startIcon={<CheckCircleIcon />}
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
                      assetType="Device"
                      values={values}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <DeviceCreationDetails
                      isSubmitting={isSubmitting}
                      values={values}
                      setFieldValue={setFieldValue}
                    />
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
                  <div>
                    <CyioCoreObjectAssetCreationExternalReferences disableAdd={true} />
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory />
                </Grid>
              </Grid>
              <div>
                <CyioCoreObjectOrCyioCoreRelationshipNotes disableAdd={true} height='100px' />
              </div>
            </>
          )}
        </Formik>
        <Dialog
          open={this.state.displayCancel}
          TransitionComponent={Transition}
          onClose={this.handleCancelButton.bind(this)}
        >
          <DialogContent>
            <Typography style={{
              fontSize: '18px',
              lineHeight: '24px',
              color: 'white',
            }} >
              {t('Are you sure you’d like to cancel?')}
            </Typography>
            <DialogContentText>
              {t('Your progress will not be saved')}
            </DialogContentText>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCancelButton.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
              onClick={() => this.props.history.push('/defender_hq/assets/devices')}
              // onClick={() => this.props.history.goBack()}
              color="secondary"
              classes={{ root: classes.buttonPopover }}
              variant="contained"
              size="small"
            >
              {t('Yes Cancel')}
            </Button>
          </DialogActions>
        </Dialog>
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
