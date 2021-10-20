import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose } from 'ramda';
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
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectCreationOverview from '../../common/stix_domain_objects/StixDomainObjectCreationOverview';
import Loader from '../../../../components/Loader';
import NetworkCreationDetails from './NetworkCreationDetails';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px',
    padding: '24px',
    height: '64px',
    backgroundColor: '#1F2842',
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
    textTransform: 'uppercase',
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

const networkCreationMutation = graphql`
  mutation NetworkCreationMutation($input: NetworkAssetAddInput) {
    createNetworkAsset(input: $input) {
      ...NetworkCard_node
    }
  }
`;

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

class NetworkCreation extends Component {
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
    console.log('Network Created Successfully! InputData: ', values);
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
            name: '',
            asset_id: '',
            version: '',
            serial_number: '',
            asset_tag: '',
            location: '',
            vendor_name: '',
            release_date: '',
            description: '',
            operational_status: '',
            createdBy: '',
            objectMarking: [],
            Labels: [],
            installed_operating_system: '',
            motherboard_id: '',
            ports: [],
            asset_type: [],
            installation_id: '',
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
                      // onClick={handleReset}
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
                    <StixDomainObjectCreationOverview
                      setFieldValue={setFieldValue}
                      values={values}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <NetworkCreationDetails setFieldValue={setFieldValue} />
                  </Grid>
                </Grid>
                {/* <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                  style={{ marginTop: 25 }}
                >
                  <Grid item={true} xs={6}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={device.id}
              stixObjectOrStixRelationshipLink={`/dashboard/assets/devices/${device.id}/knowledge`}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <StixCoreObjectOrStixCoreRelationshipLastReports
                      stixCoreObjectOrStixCoreRelationshipId={device.id}
                    />
                  </Grid>
                </Grid> */}
                {/* <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                  style={{ marginTop: 25 }}
                > */}
                {/* <Grid item={true} xs={6}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={device.id}
                    />
                  </Grid> */}
                {/* <Grid item={true} xs={6}>
                    <StixCoreObjectLatestHistory stixCoreObjectId={device.id} />
                  </Grid>
                </Grid>
                <StixCoreObjectOrStixCoreRelationshipNotes
                  stixCoreObjectOrStixCoreRelationshipId={device.id}
                /> */}
                {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <DeviceEdition deviceId={device.id} />
                </Security> */}
              </Form>
            </>
          )}
        </Formik>
      </div>
    );
  }
}

NetworkCreation.propTypes = {
  deviceId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NetworkCreation);
