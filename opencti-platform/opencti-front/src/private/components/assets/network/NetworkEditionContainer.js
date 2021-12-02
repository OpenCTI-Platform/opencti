/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
// import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { Formik, Form, Field } from 'formik';
import AppBar from '@material-ui/core/AppBar';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close, CheckCircleOutline } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import NetworkEditionOverview from './NetworkEditionOverview';
import NetworkEditionDetails from './NetworkEditionDetails';
import CyioDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetEditionOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px -24px 20px -24px',
    padding: '14px 24px 24px 24px',
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
    marginTop: -35,
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

const networkValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  asset_type: Yup.string().required(t('This field is required')),
  // implementation_point: Yup.string().required(t('This field is required')),
  // operational_status: Yup.string().required(t('This field is required')),
});

const networkEditionMutation = graphql`
  mutation NetworkEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editNetworkAsset(id: $id, input: $input) {
      name
      asset_type
      vendor_name
    }
  }
`;

class NetworkEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentTab: 0,
      open: false,
      onSubmit: false,
    };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    console.log('Network Created Successfully! InputData: ', values);
    // const finalValues = pipe(
    //   assoc('createdBy', values.createdBy?.value),
    //   assoc('objectMarking', pluck('value', values.objectMarking)),
    //   assoc('objectLabel', pluck('value', values.objectLabel)),
    // )(values);
    CM(environmentDarkLight, {
      mutation: networkEditionMutation,
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
        id: this.props.network.id,
        input: [{ key: 'name', value: 'Hello' }],
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        console.log('NetworkEditionDarkLightMutationData', data);
        this.props.history.push('/dashboard/assets/network');
      },
      onError: (err) => console.log('NetworkEditionDarkLightMutationError', err),
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
      t, classes, handleClose, network,
    } = this.props;
    console.log('NetworkEditionContainerData', network);
    // const { editContext } = network;
    const initialValues = R.pipe(
      R.assoc('id', network.id),
      R.assoc('asset_id', network.asset_id),
      R.assoc('description', network.description),
      R.assoc('name', network.name),
      R.assoc('asset_tag', network.asset_tag),
      R.assoc('asset_type', network.asset_type),
      R.assoc('location', network.locations && network.locations.map((index) => [index.description]).join('\n')),
      R.assoc('version', network.version),
      R.assoc('vendor_name', network.vendor_name),
      R.assoc('serial_number', network.serial_number),
      R.assoc('release_date', network.release_date),
      R.assoc('operational_status', network.operational_status),
      R.assoc('network_name', network.network_name),
      R.assoc('network_id', network.network_id),
      R.assoc('is_scanned', network.is_scanned),
      R.assoc('implementation_point', network.implementation_point),
      R.assoc('starting_address', network?.network_address_range?.starting_ip_address?.ip_address_value || ''),
      R.assoc('ending_address', network?.network_address_range?.ending_ip_address?.ip_address_value || ''),
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
        'network_name',
        'is_scanned',
        'network_id',
        'implementation_point',
        'starting_address',
      ]),
    )(network);
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          validationSchema={networkValidation(t)}
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
                <div>
                  <Typography
                    variant="h2"
                    gutterBottom={true}
                    classes={{ root: classes.title }}
                    style={{ float: 'left', marginTop: 10, marginRight: 5 }}
                  >
                    {t('Edit: ')}
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
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      onClick={() => this.props.history.goBack()}
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
                    {/* <NetworkEditionOverview
                network={network}
                // enableReferences={this.props.enableReferences}
                // context={editContext}
                handleClose={handleClose.bind(this)}
                /> */}
                    <CyioDomainObjectAssetEditionOverview
                      cyioDomainObject={network}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <NetworkEditionDetails
                      network={network}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
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
                  {/* <CyioCoreObjectExternalReferences
                    cyioCoreObjectId={network.id}
                  /> */}
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory cyioCoreObjectId={network.id} />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                cyioCoreObjectOrCyioCoreRelationshipId={network.id}
              />
            </>
          )}
        </Formik>
      </div>
    );
  }
}

NetworkEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  network: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const NetworkEditionFragment = createFragmentContainer(
  NetworkEditionContainer,
  {
    network: graphql`
      fragment NetworkEditionContainer_network on IntrusionSet {
        id
        ...NetworkEditionOverview_network
        ...NetworkEditionDetails_network
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
)(NetworkEditionFragment);
