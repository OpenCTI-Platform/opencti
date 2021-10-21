import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { Formik, Form, Field } from 'formik';
import AppBar from '@material-ui/core/AppBar';
import Grid from '@material-ui/core/Grid';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import NetworkEditionOverview from './NetworkEditionOverview';
import NetworkEditionDetails from './NetworkEditionDetails';
import StixDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/StixDomainObjectAssetEditionOverview';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  gridContainer: {
    marginBottom: 20,
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
});

const networkValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  asset_type: Yup.array().required(t('This field is required')),
  implementation_point: Yup.string().required(t('This field is required')),
  operational_status: Yup.string().required(t('This field is required')),
});

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
      R.assoc('location', network.locations.map((index) => [index.description]).join('\n')),
      R.assoc('version', network.version),
      R.assoc('vendor_name', network.vendor_name),
      R.assoc('serial_number', network.serial_number),
      R.assoc('release_date', network.release_date),
      R.assoc('operational_status', network.operational_status),
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
      ]),
    )(network);
    return (
      <div>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
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
                <Grid item={true} xs={6}>
                  {/* <NetworkEditionOverview
                network={network}
                // enableReferences={this.props.enableReferences}
                // context={editContext}
                handleClose={handleClose.bind(this)}
              /> */}
                  <StixDomainObjectAssetEditionOverview
                    stixDomainObject={network}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    handleClose={handleClose.bind(this)}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <NetworkEditionDetails
                    network={network}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    handleClose={handleClose.bind(this)}
                  />
                </Grid>
              </>
            )}
          </Formik>
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
              network={this.props.network}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <DeviceEditionDetails
              network={this.props.network}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )} */}
        {/* <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an network')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AppBar position="static" elevation={0} className={classes.appBar}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </AppBar>
          {this.state.currentTab === 0 && (
            <NetworkEditionOverview
              network={network}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
          {this.state.currentTab === 1 && (
            <NetworkEditionDetails
              network={network}
              enableReferences={this.props.enableReferences}
              context={editContext}
              handleClose={handleClose.bind(this)}
            />
          )}
        </div> */}
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
