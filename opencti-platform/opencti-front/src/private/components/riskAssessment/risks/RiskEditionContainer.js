/* eslint-disable */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
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
import { Close, CheckCircleOutline } from '@material-ui/icons';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat, parse } from '../../../../utils/Time';
import { adaptFieldValue } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskEditionOverview from './RiskEditionOverview';
import RiskEditionDetails from './RiskEditionDetails';

const styles = () => ({
  container: {
    margin: 0,
  },
  header: {
    margin: '-25px -24px 30px -24px',
    padding: '15px',
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
});

const riskEditionMutation = graphql`
  mutation RiskEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
      # name
      # asset_type
      # vendor_name
    }
  }
`;

const riskValidation = (t) => Yup.object().shape({
  // name: Yup.string().required(t('This field is required')),
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
class RiskEditionContainer extends Component {
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
    }
    const adaptedValues = R.evolve(
      {
        deadline: () => parse(values.deadline).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.assoc('related_risks', relatedRisks),
      R.dissoc('riskDetailsCreated'),
      R.dissoc('riskDetailsModified'),
      R.dissoc('riskDetailsDescription'),
      R.dissoc('description'),
      R.dissoc('statement'),
      R.dissoc('deadline'),
      R.dissoc('risk_status'),
      R.dissoc('false_positive'),
      R.dissoc('risk_adjusted'),
      R.dissoc('vendor_dependency'),
      R.dissoc('impacted_control_id'),
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    // const pair = Object.keys(values).map((key) => [{ key, value: values[key] }]);
    commitMutation({
      mutation: riskEditionMutation,
      variables: {
        id: this.props.risk?.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        console.log('RiskEditionDarkLightMutationData', data);
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: (err) => console.log('RiskEditionDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: riskCreationOverviewMutation,
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
      riskId,
      risk,
    } = this.props;
    const relatedRisksEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        created: value.node.created,
        modified: value.node.modified,
        name: value.node.name,
        description: value.node.description,
        statement: value.node.statement,
        risk_status: value.node.risk_status,
        deadline: value.node.deadline,
        false_positive: value.node.false_positive,
        risk_adjusted: value.node.risk_adjusted,
        vendor_dependency: value.node.vendor_dependency,
        impacted_control_id: value.node.impacted_control_id,
      })),
      R.mergeAll,
    )(risk);
    const relatedObservationsEdges = R.pipe(
      R.pathOr([], ['related_observations', 'edges']),
      R.map((value) => ({
        impacted_component: value.node.impacted_component,
        impacted_asset: value.node.subjects,
      })),
    )(risk);
    const riskDetectionSource = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.mergeAll,
      R.pathOr([], ['node', 'characterizations']),
      R.mergeAll,
      R.path(['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(risk);
    const riskEdges = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((value) => ({
        priority: value.node.priority,
      })),
      R.mergeAll,
    )(risk);
    const relatedRiskData = R.pipe(
      R.pathOr([], ['related_risks', 'edges']),
      R.map((relatedRisk) => ({
        characterization: relatedRisk.node.characterizations,
      })),
      R.mergeAll,
      R.path(['characterization']),
      R.mergeAll,
    )(risk);
    const initialValues = R.pipe(
      R.assoc('id', risk?.id || ''),
      R.assoc('poam_id', risk?.poam_id || ''),
      R.assoc('created', dateFormat(risk.created)),
      R.assoc('modified', dateFormat(risk.modified)),
      R.assoc('description', risk?.description || ''),
      R.assoc('weakness', risk?.name || ''),
      R.assoc('controls', risk?.controls || ''),
      R.assoc('risk_rating', relatedRiskData?.risk || ''),
      R.assoc('priority', riskEdges?.priority || ''),
      R.assoc('impact', relatedRiskData?.impact || ''),
      R.assoc('likelihood', relatedRiskData?.likelihood || ''),
      R.assoc('name', relatedRisksEdges.name || ''),
      R.assoc('riskDetailsCreated', dateFormat(relatedRisksEdges.created)),
      R.assoc('riskDetailsModified', dateFormat(relatedRisksEdges.modified)),
      R.assoc('riskDetailsDescription', relatedRisksEdges.description || ''),
      R.assoc('statement', relatedRisksEdges.statement || ''),
      R.assoc('risk_status', relatedRisksEdges.risk_status || ''),
      R.assoc('deadline', dateFormat(relatedRisksEdges?.deadline)),
      R.assoc('detection_source', riskDetectionSource?.actor.name || ''),
      R.assoc('impacted_control', relatedRisksEdges?.impacted_control_id || ''),
      R.assoc('false_positive', relatedRisksEdges?.false_positive || ''),
      R.assoc('operationally_required', risk?.operationally_required || ''),
      R.assoc('risk_adjusted', relatedRisksEdges?.risk_adjusted || ''),
      R.assoc('vendor_dependency', relatedRisksEdges?.vendor_dependency || ''),
      R.pick([
        'id',
        'poam_id',
        'created',
        'modified',
        'description',
        'weakness',
        'controls',
        'risk_rating',
        'priority',
        'impact',
        'likelihood',
        'labels',
        'name',
        'riskDetailsCreated',
        'riskDetailsModified',
        'riskDetailsDescription',
        'statement',
        'risk_status',
        'deadline',
        'impacted_assets',
        'detection_source',
        'impacted_control',
        'false_positive',
        'operationally_required',
        'risk_adjusted',
        'vendor_dependency',
      ]),
    )(risk);
    // const { editContext } = risk;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          validationSchema={riskValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({
            submitForm,
            isSubmitting,
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
                    name="weakness"
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
                      // onClick={() => this.props.history.goBack()}
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
                    <RiskEditionOverview
                      risk={risk}
                      values={values}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <RiskEditionDetails
                      risk={risk}
                      values={values}
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
                    fieldName='links'
                    externalReferences={risk.links}
                    cyioCoreObjectId={riskId}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk?.id} /> */}
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    notes={risk.remarks}
                    fieldName='remarks'
                    cyioCoreObjectOrCyioCoreRelationshipId={riskId}
                    marginTop='0px'
                  />
                </Grid>
              </Grid>
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
            </>
          )}
        </Formik>
      </div>
    );
  }
}

RiskEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  risk: PropTypes.object,
  riskId: PropTypes.string,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RiskEditionFragment = createFragmentContainer(
  RiskEditionContainer,
  {
    risk: graphql`
      fragment RiskEditionContainer_risk on POAMItem {
        id
        created
        modified
        poam_id     # Item ID
        name        # Weakness
        description
        labels {
          id
          name
          color
          description
        }
        origins {
          id
          origin_actors {       # only use if UI support Detection Source
            actor_type
            actor_ref {
              ... on AssessmentPlatform {
                id
                name
              }
              ... on Component {
                id
                component_type
                name
              }
              ... on OscalParty {
                id
                party_type
                name
              }
            }
          }
        }
        links {
          id
          created
          modified
          external_id     # external id
          source_name     # Title
          description     # description
          url             # URL
          media_type      # Media Type
        }
        remarks {
          id
          abstract
          content
          authors
        }
        related_risks {
          edges {
            node{
              id
              created
              modified
              name
              description
              statement
              risk_status       # Risk Status
              deadline
              priority
              impacted_control_id
              accepted
              false_positive    # False-Positive
              risk_adjusted     # Operational Required
              vendor_dependency # Vendor Dependency
              characterizations {
                origins {
                  id
                  origin_actors {
                    actor_type
                    actor_ref {
                      ... on AssessmentPlatform {
                        id
                        name
                      }
                      ... on Component {
                        id
                        component_type
                        name          # Detection Source
                      }
                      ... on OscalParty {
                      id
                      party_type
                      name            # Detection Source
                      }
                    }
                  }
                }
                facets {
                  id
                  source_system
                  facet_name
                  facet_value
                  risk_state
                  entity_type
                }
              }
              remediations {
                response_type
                lifecycle
              }
            }
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RiskEditionFragment);
