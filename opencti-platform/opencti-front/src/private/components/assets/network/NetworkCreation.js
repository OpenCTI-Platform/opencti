/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose } from 'ramda';
import { Formik, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { Close } from '@material-ui/icons';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
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
import NetworkCreationDetails from './NetworkCreationDetails';
import { toastGenericError } from "../../../../utils/bakedToast";

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  header: {
    height: '70px',
    display: 'flex',
    margin: '0 -1.5rem 1rem -1.5rem',
    padding: '1rem 1.5rem',
    backgroundColor: theme.palette.background.paper,
    justifyContent: 'space-between',
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
  buttonPopover: {
    textTransform: 'capitalize',
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

const networkValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  asset_type: Yup.string().required(t('This field is required')),
  network_id: Yup.string().required(t('This field is required')),
  network_name: Yup.string().required(t('This field is required')),
  is_scanned: Yup.boolean().required(t('This field is required')),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class NetworkCreation extends Component {
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

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const network_ipv4_address_range = {
      starting_ip_address: {
        ip_address_value: values?.starting_address
      },
      ending_ip_address: {
        ip_address_value: values?.ending_address
      }
    }
    const adaptedValues = R.evolve(
      {
        release_date: () => values.release_date === null ? null : parse(values.release_date).format(),
        last_scanned: () => values.last_scanned === null ? null : parse(values.last_scanned).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.dissoc('starting_address'),
      R.dissoc('ending_address'),
      R.dissoc('labels'),
      R.assoc('network_ipv4_address_range', network_ipv4_address_range),
    )(adaptedValues);
    commitMutation({
      mutation: networkCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/defender_hq/assets/network');
      },
      pathname:'/defender_hq/assets/network',
      onError: () => {
        toastGenericError('Failed to Create Network');
      }
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
      classes
    } = this.props;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            name: '',
            asset_id: '',
            asset_type: 'network',
            asset_tag: '',
            description: '',
            version: '',
            serial_number: '',
            vendor_name: '',
            release_date: null,
            operational_status: '',
            implementation_point: 'internal',
            network_id: '',
            network_name: '',
            labels: [],
            starting_address: '',
            ending_address: '',
            is_scanned: false,
            last_scanned: null,
          }}
          validationSchema={networkValidation(t)}
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
                <Typography
                  variant="h1"
                  gutterBottom={true}
                  className={classes.leftContainer}
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
              onClick={() => this.props.history.push('/defender_hq/assets/network')}
              // onClick={() => history.goBack()}
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
