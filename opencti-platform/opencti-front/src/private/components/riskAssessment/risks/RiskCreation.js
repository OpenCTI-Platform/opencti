import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import { compose, evolve } from 'ramda';
import { Formik, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import {
  Close,
  CheckCircleOutline,
} from '@material-ui/icons';
import Typography from '@material-ui/core/Typography';
import Dialog from '@material-ui/core/Dialog';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import graphql from 'babel-plugin-relay/macro';
import { parse } from '../../../../utils/Time';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import RiskCreationOverview from './RiskCreationOverview';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectAssetCreationExternalReferences from '../../analysis/external_references/CyioCoreObjectAssetCreationExternalReferences';
import RiskCreationDetails from './RiskCreationDetails';

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
    marginTop: '-10px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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

const riskCreationMutation = graphql`
  mutation RiskCreationMutation($input: RiskAddInput) {
    createRisk (input: $input) {
      id
      # ...RiskCard_node
      # ...RiskDetails_risk
      # operational_status
      # serial_number
      # release_date
      # description
      # version
      # name
    }
  }
`;

const riskValidation = (t) => Yup.object().shape({
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
const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class RiskCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
    };
  }

  handleCancelButton() {
    this.setState({ displayCancel: false });
  }

  handleOpenCancelButton() {
    this.setState({ displayCancel: true });
  }

  handleOpen() {
    this.setState({ open: true });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = evolve(
      {
        deadline: () => parse(values.deadline).format(),
      },
      values,
    );
    const relatedRisks = {
      created: values.riskDetailsCreated,
      modified: values.riskDetailsModified,
      name: values.riskDetailsDescription,
      description: values.description,
      statement: values.statement,
      risk_status: values.risk_status,
      deadline: values.deadline,
      false_positive: values.false_positive,
      risk_adjusted: values.risk_adjusted,
      vendor_dependency: values.vendor_dependency,
      impacted_control_id: values.impacted_control_id,
      characterizations: {
        facets: {
          name: {
            risk_rating: values.risk_rating,
            impact: values.impact,
            likelihood: values.likelihood,
          },
        },
        origins: {
          origin_actors: {
            actor: {
              detection_source: values.detection_source,
            },
          },
        },
      },
      // remediations: {
      //   response_type: values.response_type,
      //   lifecycle: values.lifecycle,
      // }
    };
    const finalValues = R.pipe(
      R.dissoc('controls'),
      R.assoc('name', values.name),
      R.assoc('related_risks', relatedRisks),
      R.dissoc('riskDetailsCreated'),
      R.dissoc('riskDetailsModified'),
      R.dissoc('riskDetailsDescription'),
      R.dissoc('detection_source'),
      R.dissoc('risk_rating'),
      R.dissoc('impace'),
      R.dissoc('likelihood'),
      R.dissoc('description'),
      R.dissoc('statement'),
      R.dissoc('deadline'),
      R.dissoc('risk_status'),
      R.dissoc('false_positive'),
      R.dissoc('risk_adjusted'),
      R.dissoc('vendor_dependency'),
      R.dissoc('impacted_control_id'),
    )(adaptedValues);
    commitMutation({
      mutation: riskCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: () => {},
    });
    // commitMutation({
    //   mutation: riskCreationMutation,
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
      riskId,
    } = this.props;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={{
            name: '',
            poam_id: '',
            created: null,
            modified: null,
            description: '',
            weakness: '',
            controls: [],
            risk_rating: '',
            priority: 1,
            impact: '',
            likelihood: '',
            labels: [],
            riskDetailsCreated: null,
            riskDetailsModified: null,
            riskDetailsDescription: '',
            statement: '',
            risk_status: 'open',
            deadline: null,
            impacted_assets: '',
            detection_source: '',
            impacted_control: '',
            false_positive: 'approved',
            operationally_required: '',
            risk_adjusted: 'pending',
            vendor_dependency: 'pending',
          }}
          validationSchema={riskValidation(t)}
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
                  classes={{ root: classes.title }}
                >
                  {t('New Risk')}
                </Typography>
                <div className={classes.rightContainer}>
                  <Tooltip title={t('Cancel')}>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<Close />}
                      color='primary'
                      // onClick={() => history.goBack()}
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
                    <RiskCreationOverview
                      setFieldValue={setFieldValue}
                      values={values}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <RiskCreationDetails values={values} setFieldValue={setFieldValue} />
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
                  {/* <CyioExternalReferences
                      cyioCoreObjectId={risk.id}
                    /> */}
                  <CyioCoreObjectAssetCreationExternalReferences
                    cyioCoreObjectId={riskId}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    cyioCoreObjectOrCyioCoreRelationshipId={riskId}
                    marginTop='0px'
                  />
                </Grid>
              </Grid>
            </>
          )}
        </Formik>
        <Dialog
          open={this.state.displayCancel}
          TransitionComponent={Transition}
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
              // onClick={this.handleCloseDelete.bind(this)}
              // disabled={this.state.deleting}
              onClick={this.handleCancelButton.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
              // onClick={this.submitDelete.bind(this)}
              // disabled={this.state.deleting}
              onClick={() => this.props.history.goBack()}
              color="primary"
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

RiskCreation.propTypes = {
  riskId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RiskCreation);
