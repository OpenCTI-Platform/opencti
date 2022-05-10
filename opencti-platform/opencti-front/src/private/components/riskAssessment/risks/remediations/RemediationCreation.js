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
import {toastGenericError} from "../../../../../utils/bakedToast";
import {
  commitMutation,
  QueryRenderer,
} from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import StixDomainObjectHeader from '../../../common/stix_domain_objects/StixDomainObjectHeader';
import RemediationCreationGeneral from './RemediationCreationGeneral';
import RelatedTasks from './RelatedTasks';
import RequiredResources from './RequiredResources';
import CyioCoreObjectLatestHistory from '../../../common/stix_core_objects/CyioCoreObjectLatestHistory';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectAssetCreationExternalReferences from '../../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import Loader from '../../../../../components/Loader';
import RemediationCreationDetails from './RemediationCreationDetails';
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
  <Slide direction='up' ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const remediationCreationMutation = graphql`
  mutation RemediationCreationMutation($input: RiskResponseAddInput) {
    createRiskResponse(input: $input) {
      id
    }
  }
`;

const remediationValidation = (t) =>
  Yup.object().shape({
     name: Yup.string().required(t('This field is required')),
     actor_type: Yup.string().required(t('This field is required')),
     actor_ref: Yup.string().required(t('This field is required')),
     response_type: Yup.string().required(t('This field is required')),
     lifecycle: Yup.string().required(t('This field is required')),
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
      
    const adaptedValues = R.pickAll(['actor_ref','actor_type'], values)
   
    const finalValues = R.pipe(
      R.dissoc('created'),
      R.dissoc('modified'),
      R.dissoc('actor_ref'),
      R.dissoc('actor_target'),
      R.dissoc('actor_type'),
      R.dissoc('oscal_type'),
      R.dissoc('oscal_party'),
      R.assoc('origins', [{'origin_actors':[adaptedValues]}])
    )(values);
console.log('Final', finalValues)
    CM(environmentDarkLight, {
      mutation: remediationCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/activities/risk assessment/risks/' + this.props.riskId.id);
      },
      onError: (err) => {
        toastGenericError("Failed to create Remediation")
      }
    });
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
    const { t, classes, remediationId, open, history, riskId } = this.props;
    const risk_id = this.props.riskId;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            risk_id: riskId.id,
            response_type: '',
            lifecycle: '',
            name: '',
            description: '',
            created: null,
            modified: null,
            actor_type: '',
            actor_ref: '',
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
                  variant='h1'
                  color='secondary'
                  gutterBottom={true}
                  classes={{ root: classes.title }}
                >
                  {t('New Remediation')}
                </Typography>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant='outlined'
                      size='small'
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
                      variant='contained'
                      color='primary'
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
                      <Typography className={classes.popoverDialog}>
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
                        variant='outlined'
                        size='small'
                      >
                        {t('Go Back')}
                      </Button>
                      <Button
                        color='secondary'
                        // disabled={this.state.deleting}
                        onClick={() => history.goBack()}
                        classes={{ root: classes.buttonPopover }}
                        variant='contained'
                        size='small'
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
                  <Grid item={true} xs={12}>
                    <RemediationCreationGeneral
                      setFieldValue={setFieldValue}
                      values={values}
                      remediationId={remediationId}
                    />
                  </Grid>
                  {/* <Grid item={true} xs={6}>
                    <RemediationCreationDetails
                      setFieldValue={setFieldValue}
                      values={values}
                    />
                  </Grid> */}
                </Grid>
              </Form>
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 25 }}
              >
                <Grid
                  style={{ pointerEvents: 'none', opacity: '0.4' }}
                  item={true}
                  xs={6}
                >
                  {/* <StixCoreObjectExternalReferences
                      stixCoreObjectId={remediation.id}
                    /> */}
                  {/* <CyioCoreObjectAssetCreationExternalReferences /> */}
                  <RequiredResources remediationId={remediationId} />
                </Grid>
                <Grid
                  style={{ pointerEvents: 'none', opacity: '0.4' }}
                  item={true}
                  xs={6}
                >
                  {/* <CyioCoreObjectLatestHistory /> */}
                  <RelatedTasks remediationId={remediationId} />
                </Grid>
              </Grid>
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 50 }}
              >
                <Grid
                  style={{ pointerEvents: 'none', opacity: '0.4' }}
                  item={true}
                  xs={6}
                >
                  <CyioCoreObjectAssetCreationExternalReferences />
                  {/* <CyioCoreObjectExternalReferences
                    cyioCoreObjectId={remediationId}
                  /> */}
                </Grid>
                <Grid
                  style={{ pointerEvents: 'none', opacity: '0.4' }}
                  item={true}
                  xs={6}
                >
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
                    marginTop='0px'
                  />
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
  riskId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true })
)(RemediationCreation);
