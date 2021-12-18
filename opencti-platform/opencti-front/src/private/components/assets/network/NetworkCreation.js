/* eslint-disable */
/* refactor */
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
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioDomainObjectAssetCreationOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetCreationOverview';
import Loader from '../../../../components/Loader';
import CyioCoreObjectAssetCreationExternalReferences from '../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import NetworkCreationDetails from './NetworkCreationDetails';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px -24px 20px -24px',
    padding: '23px 24px 24px 24px',
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
      ...NetworkDetails_network
      operational_status
      serial_number
      release_date
      description
      version
      name
    }
  }
`;

const deviceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  // asset_type: Yup.array().required(t('This field is required')),
  // implementation_point: Yup.string().required(t('This field is required')),
  // operational_status: Yup.string().required(t('This field is required')),
  // first_seen: Yup.date()
  //   .nullable()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)')),
  // last_seen: Yup.date()
  //   .nullable()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)')),
  // sophistication: Yup.string().nullable(),
  // resource_level: Yup.string().nullable(),
  // primary_motivation: Yup.string().nullable(),
  // secondary_motivations: Yup.array().nullable(),
  // personal_motivations: Yup.array().nullable(),
  // goals: Yup.string().nullable(),
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
    // const finalValues = pipe(
    //   assoc('createdBy', values.createdBy?.value),
    //   assoc('objectMarking', pluck('value', values.objectMarking)),
    //   assoc('objectLabel', pluck('value', values.objectLabel)),
    // )(values);
    CM(environmentDarkLight, {
      mutation: networkCreationMutation,
      // const adaptedValues = evolve(
      //   {
      //     published: () => parse(values.published).format(),
      //     createdBy: path(['value']),
      //     objectMarking: pluck('value'),
      //     objectLabel: pluck('value'),
      //   },
      //   values,
      // );
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/dashboard/assets/network');
      },
      onError: (err) => console.log('NetworkCreationDarkLightMutationError', err),
    });
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
            name: 'Hello World',
            // asset_id: '',
            // version: '',
            // serial_number: '',
            // asset_tag: '',
            // location: '',
            // vendor_name: '',
            // release_date: '',
            // description: '',
            operational_status: 'other',
            implementation_point: 'external',
            network_id: '12345',
            network_name: 'test_net',
            // Labels: [],
            // ports: [],
            asset_type: 'network',
            // installation_id: '',
            // fqdn: '',
            // is_scanned: false,
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
                    <CyioDomainObjectAssetCreationOverview
                      setFieldValue={setFieldValue}
                      values={values}
                      assetType="Network"
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <NetworkCreationDetails setFieldValue={setFieldValue} />
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
