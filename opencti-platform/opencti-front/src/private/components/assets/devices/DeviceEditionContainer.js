/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import { Close } from '@material-ui/icons';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import { createFragmentContainer } from 'react-relay';
import { adaptFieldValue } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { dateFormat, parse } from '../../../../utils/Time';
import TextField from '../../../../components/TextField';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import DeviceEditionDetails from './DeviceEditionDetails';
import CyioDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetEditionOverview';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1rem 1.5rem',
    height: '70px',
    backgroundColor: theme.palette.background.paper,
  },
  gridContainer: {
    marginBottom: 20,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    marginTop: -35,
  },
  title: {
    float: 'left',
  },
  leftContainer: {
    display: 'flex',
    alignItems: 'center',
  },
  rightContainer: {
    float: 'right',
    marginTop: '-5px',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
});

const deviceEditionMutation = graphql`
  mutation DeviceEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editHardwareAsset(id: $id, input: $input) {
      id
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
class DeviceEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
      totalInitial: {},
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const filteredValue = {};
    const { totalInitial } = this.state;
    Object.keys(totalInitial).forEach((key, j) => {
      if (Array.isArray(values[key])) {
        if (values[key].some((value, i) => value !== totalInitial[key][i])) {
          filteredValue[key] = values[key];
        }
      }
      if (!Array.isArray(values[key]) && totalInitial[key] !== values[key]) {
        filteredValue[key] = values[key];
      }
    });
    const adaptedValues = R.evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
        ipv4_address: () => values.ipv4_address.length > 0 ? values.ipv4_address.map((address) => JSON.stringify({ ip_address_value: address })) : [],
        ipv6_address: () => values.ipv6_address.length > 0 ? values.ipv6_address.map((address) => JSON.stringify({ ip_address_value: address })) : [],
        ports: () => values.ports.length > 0 ? values.ports.map((port) => JSON.stringify(port)) : [],
      },
      filteredValue,
    );
    const finalValues = R.pipe(
      R.dissoc('id'),
      R.dissoc('locations'),
      R.dissoc('protocols'),
      R.dissoc('port_number'),
      R.dissoc('responsible_parties'),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': Array.isArray(adaptFieldValue(n[1])) ? adaptFieldValue(n[1]) : [adaptFieldValue(n[1])],
      })),
    )(adaptedValues);
    commitMutation({
      mutation: deviceEditionMutation,
      variables: {
        id: this.props.device?.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/defender HQ/assets/devices');
      },
    });
    // commitMutation({
    //   mutation: deviceEditionMutation,
    //   variables: {
    //     input: finalValues,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_computingDeviceAssetList',
    //     this.props.paginationOptions,
    //     'editComputingDeviceAsset',
    //   ),
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
      t, classes, handleClose, device, refreshQuery,
    } = this.props;
    const installedHardwares = R.pipe(
      R.pathOr([], ['installed_hardware']),
      R.map((n) => (n.id)),
    )(device);
    const installedSoftware = R.pipe(
      R.pathOr([], ['installed_software']),
      R.map((n) => (n.id)),
    )(device);
    const labels = R.pipe(
      R.pathOr([], ['labels']),
      R.map((n) => (n.id)),
    )(device);
    const initialValues = R.pipe(
      R.assoc('id', device?.id || ''),
      R.assoc('asset_id', device?.asset_id || ''),
      R.assoc('description', device?.description || ''),
      R.assoc('name', device?.name || ''),
      R.assoc('asset_tag', device?.asset_tag || ''),
      R.assoc('asset_type', device?.asset_type || ''),
      R.assoc('locations', device?.locations && device?.locations.map((location) => [location.street_address, location.city, location.country, location.postal_code]).join('\n')),
      R.assoc('version', device?.version || ''),
      R.assoc('labels', labels),
      R.assoc('vendor_name', device?.vendor_name || ''),
      R.assoc('cpe_identifier', device?.cpe_identifier || ''),
      R.assoc('serial_number', device?.serial_number || ''),
      R.assoc('release_date', dateFormat(device?.release_date)),
      R.assoc('installed_hardware', installedHardwares || []),
      R.assoc('installed_software', installedSoftware || []),
      R.assoc('installed_operating_system', device?.installed_operating_system?.id || ''),
      R.assoc('operational_status', device?.operational_status),
      R.assoc('installation_id', device?.installation_id || ''),
      R.assoc('bios_id', device?.bios_id || ''),
      R.assoc('connected_to_network', device?.connected_to_network?.name || ''),
      R.assoc('netbios_name', device?.netbios_name || ''),
      R.assoc('baseline_configuration_name', device?.baseline_configuration_name || ''),
      R.assoc('mac_address', device?.mac_address || []),
      R.assoc('model', device?.model || ''),
      R.assoc('ports', device?.ports.length > 0 ? device.ports : []),
      R.assoc('port_number', ''),
      R.assoc('protocols', []),
      R.assoc('hostname', device?.hostname || ''),
      R.assoc('default_gateway', device?.default_gateway || ''),
      R.assoc('motherboard_id', device?.motherboard_id || ''),
      R.assoc('is_scanned', device?.is_scanned || false),
      R.assoc('last_scanned', device?.last_scanned),
      R.assoc('is_virtual', device?.is_virtual || false),
      R.assoc('is_publicly_accessible', device?.is_publicly_accessible || false),
      R.assoc('uri', device?.uri || null),
      R.assoc('fqdn', device?.fqdn || ''),
      R.assoc('ipv4_address', R.pluck('ip_address_value', device?.ipv4_address || [])),
      R.assoc('ipv6_address', R.pluck('ip_address_value', device?.ipv6_address || [])),
      R.assoc('responsible_parties', ''),
      R.assoc('implementation_point', device?.implementation_point),
      R.pick([
        'id',
        'asset_id',
        'name',
        'fqdn',
        'description',
        'asset_tag',
        'asset_type',
        'locations',
        'cpe_identifier',
        'labels',
        'version',
        'vendor_name',
        'serial_number',
        'release_date',
        'port_number',
        'protocols',
        'ports',
        'installed_operating_system',
        'ipv4_address',
        'ipv6_address',
        'operational_status',
        'installation_id',
        'connected_to_network',
        'bios_id',
        'installed_software',
        'netbios_name',
        'baseline_configuration_name',
        'mac_address',
        'model',
        'installed_hardware',
        'hostname',
        'default_gateway',
        'motherboard_id',
        'is_scanned',
        'last_scanned',
        'is_virtual',
        'is_publicly_accessible',
        'resposnible_parties',
        'uri',
        'implementation_point',
      ]),
    )(device);
    // const { editContext } = device;
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
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <>
              <div className={classes.header}>
                <div className={classes.leftContainer}>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    classes={{ root: classes.title }}
                    style={{ float: 'left', marginTop: 10, marginRight: 5 }}
                  >
                    {t('EDIT: ')}
                  </Typography>
                  <Field
                    component={TextField}
                    variant='outlined'
                    name="name"
                    size='small'
                    containerstyle={{ width: '50%' }}
                  />
                </div>
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
                      onClick={() => this.setState({ totalInitial: initialValues }, submitForm)}
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
                    <CyioDomainObjectAssetEditionOverview
                      cyioDomainObject={device}
                      assetType="Device"
                      refreshQuery={refreshQuery}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <DeviceEditionDetails
                      setFieldValue={setFieldValue}
                      values={values}
                      isSubmitting={isSubmitting}
                      device={device}
                      // enableReferences={this.props.enableReferences}
                      // context={editContext}
                      handleClose={handleClose.bind(this)}
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
                  <CyioCoreObjectExternalReferences
                    externalReferences={device.external_references}
                    cyioCoreObjectId={device?.id}
                    fieldName='external_references'
                    typename={device.__typename}
                    refreshQuery={refreshQuery}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory cyioCoreObjectId={device?.id} />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={device.__typename}
                refreshQuery={refreshQuery}
                fieldName='notes'
                notes={device.notes}
                cyioCoreObjectOrCyioCoreRelationshipId={device?.id}
              />
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
              onClick={() => this.props.history.goBack()}
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

DeviceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  device: PropTypes.object,
  refreshQuery: PropTypes.func,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const DeviceEditionFragment = createFragmentContainer(
  DeviceEditionContainer,
  {
    device: graphql`
      fragment DeviceEditionContainer_device on HardwareAsset {
        __typename
        id
        name
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        external_references {
          __typename
          id
          source_name
          description
          entity_type
          url
          hashes {
            value
          }
          external_id
        }
        notes {
          __typename
          id
          # created
          # modified
          entity_type
          abstract
          content
          authors
        }
        asset_id
        network_id
        description
        version
        vendor_name
        asset_tag
        cpe_identifier
        asset_type
        serial_number
        release_date
        installed_software {
          id
          name
        }
        related_risks {
          id
          name
        }
        installed_hardware {
          id
          name
          uri
        }
        installed_operating_system {
          id
          name
          vendor_name
        }
        locations {
          city
          country
          postal_code
          street_address
        }
        ipv4_address {
          ip_address_value
        }
        ipv6_address {
          ip_address_value
        }
        operational_status
        connected_to_network {
          name
        }
        ports {
          port_number
          protocols
        }
        uri
        model
        mac_address
        fqdn
        baseline_configuration_name
        bios_id
        is_scanned
        last_scanned
        hostname
        default_gateway
        motherboard_id
        installation_id
        netbios_name
        is_virtual
        is_publicly_accessible
        implementation_point
        # ...DeviceEditionOverview_device
        # ...DeviceEditionDetails_device
        # editContext {
        #   name
        #   focusOn
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceEditionFragment);
