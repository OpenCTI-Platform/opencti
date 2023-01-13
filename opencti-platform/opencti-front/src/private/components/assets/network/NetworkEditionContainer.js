/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { Formik, Form, Field } from 'formik';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { Close } from '@material-ui/icons';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import inject18n from '../../../../components/i18n';
import { adaptFieldValue } from '../../../../utils/String';
import { dateFormat, parse } from '../../../../utils/Time';
import TextField from '../../../../components/TextField';
import NetworkEditionDetails from './NetworkEditionDetails';
import CyioDomainObjectAssetEditionOverview from '../../common/stix_domain_objects/CyioDomainObjectAssetEditionOverview';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectLatestHistory from '../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import { commitMutation } from '../../../../relay/environment';

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
  network_id: Yup.string().required(t('This field is required')),
  network_name: Yup.string().required(t('This field is required')),
  is_scanned: Yup.boolean().required(t('This field is required')),
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

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class NetworkEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentTab: 0,
      open: false,
      onSubmit: false,
      displayCancel: false,
      totalInitial: {},
    };
  }

  handleChangeTab(value) {
    this.setState({ currentTab: value });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const filteredValue = {};
    const { totalInitial } = this.state;
    const network_ipv4_address_range = {
      starting_ip_address: {
        ip_address_value: values?.starting_address,
      },
      ending_ip_address: {
        ip_address_value: values?.ending_address,
      },
    };
    const adaptedValues = R.evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
      },
      values,
    );
    Object.keys(totalInitial).forEach((key, j) => {
      if (Array.isArray(adaptedValues[key])) {
        if (adaptedValues[key].some((value, i) => value !== totalInitial[key][i])) {
          filteredValue[key] = adaptedValues[key];
        }
      }
      if (!Array.isArray(adaptedValues[key]) && totalInitial[key] !== adaptedValues[key]) {
        filteredValue[key] = adaptedValues[key];
      }
    });
    const finalValues = R.pipe(
      R.dissoc('id'),
      R.dissoc('starting_address'),
      R.dissoc('ending_address'),
      R.assoc('network_ipv4_address_range', JSON.stringify(network_ipv4_address_range)),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': Array.isArray(adaptFieldValue(n[1])) ? adaptFieldValue(n[1]) : [adaptFieldValue(n[1])],
      })),
    )(filteredValue);
    commitMutation({
      mutation: networkEditionMutation,
      variables: {
        id: this.props.network.id,
        input: finalValues,
      },
      setSubmitting,
      pathname: '/defender HQ/assets/network',
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/defender HQ/assets/network');
      },
      onError: (err) => console.error(err),
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

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const {
      t, classes, network, refreshQuery,
    } = this.props;
    // const { editContext } = network;
    const initialValues = R.pipe(
      R.assoc('id', network?.id),
      R.assoc('asset_id', network?.asset_id),
      R.assoc('description', network?.description),
      R.assoc('name', network?.name),
      R.assoc('asset_tag', network?.asset_tag),
      R.assoc('asset_type', network?.asset_type),
      R.assoc('location', network?.locations && network.locations.map((index) => [index.description]).join('\n')),
      R.assoc('version', network?.version),
      R.assoc('vendor_name', network?.vendor_name),
      R.assoc('serial_number', network?.serial_number),
      R.assoc('release_date', dateFormat(network?.release_date)),
      R.assoc('operational_status', network?.operational_status),
      R.assoc('network_name', network?.network_name),
      R.assoc('network_id', network?.network_id),
      R.assoc('is_scanned', network?.is_scanned),
      R.assoc('last_scanned', network?.last_scanned),
      R.assoc('implementation_point', network?.implementation_point),
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
        'last_scanned',
        'network_id',
        'implementation_point',
        'starting_address',
        'ending_address',
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
          {({ submitForm, isSubmitting, setFieldValue }) => (
            <>
              <div className={classes.header}>
                <div>
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
                      cyioDomainObject={network}
                      refreshQuery={refreshQuery}
                      assetType="Network"
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <NetworkEditionDetails
                      network={network}
                      setFieldValue={setFieldValue}
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
                  <CyioCoreObjectExternalReferences
                    externalReferences={network.external_references}
                    cyioCoreObjectId={network.id}
                    fieldName='external_references'
                    refreshQuery={refreshQuery}
                    typename={network.__typename}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectLatestHistory cyioCoreObjectId={network.id} />
                </Grid>
              </Grid>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={network.__typename}
                refreshQuery={refreshQuery}
                fieldName='notes'
                notes={network.notes}
                cyioCoreObjectOrCyioCoreRelationshipId={network.id}
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

NetworkEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  refreshQuery: PropTypes.func,
  classes: PropTypes.object,
  network: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const NetworkEditionFragment = createFragmentContainer(
  NetworkEditionContainer,
  {
    network: graphql`
      fragment NetworkEditionContainer_network on NetworkAsset {
        __typename
        id
        name
        asset_id
        network_id
        description
        locations {
          description
        }
        version
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
        vendor_name
        asset_tag
        asset_type
        serial_number
        release_date
        operational_status
        network_name
        network_id
        is_scanned
        last_scanned
        implementation_point
        network_address_range {
          ending_ip_address{
            ... on IpV4Address {
              ip_address_value
            }
          }
          starting_ip_address{
            ... on IpV4Address {
              ip_address_value
            }
          }
        }
        # ...NetworkEditionOverview_network
        # ...NetworkEditionDetails_network
        # editContext {
        #   name
        #   focusOn
        # }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NetworkEditionFragment);
