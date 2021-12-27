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
import Slide from '@material-ui/core/Slide';
import Dialog from '@material-ui/core/Dialog';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import Button from '@material-ui/core/Button';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import { dayStartDate, parse } from '../../../../../utils/Time';
import { commitMutation, QueryRenderer } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import StixDomainObjectHeader from '../../../common/stix_domain_objects/StixDomainObjectHeader';
import RemediationCreationGeneral from './RemediationCreationGeneral';
import RelatedTasks from './RelatedTasks';
import RequiredResources from './RequiredResources';
import CyioCoreObjectLatestHistory from '../../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectAssetCreationExternalReferences from '../../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import Loader from '../../../../../components/Loader';
// import RemediationCreationDetails from './RemediationCreationDetails';

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
  buttonPopover: {
    textTransform: 'capitalize',
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
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  title: {
    float: 'left',
    textTransform: 'capitalize',
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

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const remediationCreationMutation = graphql`
  mutation RemediationCreationMutation($input: ComputingDeviceAssetAddInput) {
    createComputingDeviceAsset (input: $input) {
      # ...RemediationDetails_remediation
      operational_status
      serial_number
      release_date
      description
      version
      name
    }
  }
`;

const remediationValidation = (t) => Yup.object().shape({
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

class RemediationCreation extends Component {
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
      // mutation: remediationCreationMutation,
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
        this.props.history.push('/dashboard/risk-assessment/risks/');
      },
      onError: (err) => console.log('RemediationCreationDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: remediationCreationMutation,
    //   variables: {
    //     input: values,
    //   },
    // //   // updater: (store) => insertNode(
    // //   //   store,
    // //   //   'Pagination_threatActors',
    // //   //   this.props.paginationOptions,
    // //   //   'threatActorAdd',
    // //   // ),
    //   setSubmitting,
    //   onCompleted: () => {
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
      remediationId,
      open,
      history,
    } = this.props;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            name: 'Hello World',
            operational_status: 'other',
            implementation_point: 'external',
            ipv4_address: [],
            ipv6_address: [],
            ports: [],
            asset_type: 'physical-devices',
            mac_address: [],
          }}
          validationSchema={remediationValidation(t)}
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
                  color="secondary"
                  gutterBottom={true}
                  classes={{ root: classes.title }}
                >
                  {t('New Remediation')}
                </Typography>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      // onClick={() => history.goBack()}
                      onClick={this.handleOpen.bind(this)}
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
                  <Dialog
                    open={this.state.open}
                    keepMounted={true}
                    TransitionComponent={Transition}
                    onClose={this.handleClose.bind(this)}
                  >
                    <DialogContent>
                      <Typography className={classes.popoverDialog} >
                        {t('Are you sure you’d like to cancel?')}
                      </Typography>
                      <DialogContentText>
                        {t('Your progress will not be saved')}
                      </DialogContentText>
                    </DialogContent>
                    <DialogActions className={classes.dialogActions}>
                      <Button
                        onClick={this.handleClose.bind(this)}
                        // disabled={this.state.deleting}
                        classes={{ root: classes.buttonPopover }}
                        variant="outlined"
                        size="small"
                      >
                        {t('Go Back')}
                      </Button>
                      <Button
                        color="secondary"
                        // disabled={this.state.deleting}
                        onClick={() => history.goBack()}
                        classes={{ root: classes.buttonPopover }}
                        variant="contained"
                        size="small"
                      >
                        {t('Yes, Cancel')}
                      </Button>
                    </DialogActions>
                  </Dialog>
                </div>
              </div>
              <Form>
                <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                >
                  <Grid item={true} xs={6}>
              {/* <RemediationCreationOverview setFieldValue={setFieldValue} values={values} /> */}
                    <RemediationCreationGeneral
                      setFieldValue={setFieldValue}
                      values={values}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    {/* <RemediationCreationDetails setFieldValue={setFieldValue} /> */}
                    <CyioCoreObjectOrCyioCoreRelationshipNotes
                      cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
                      marginTop="0px"
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
                      stixCoreObjectId={remediation.id}
                    /> */}
                  {/* <CyioCoreObjectAssetCreationExternalReferences /> */}
                  <RequiredResources remediationId={remediationId}/>
                </Grid>
                <Grid item={true} xs={6}>
                  {/* <CyioCoreObjectLatestHistory /> */}
                  <RelatedTasks remediationId={remediationId}/>
                </Grid>
              </Grid>
            </>
          )}
        </Formik>
      </div>
    );
  }
}

RemediationCreation.propTypes = {
  remediationId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RemediationCreation);
