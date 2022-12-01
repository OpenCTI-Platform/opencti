/* eslint-disable */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Yup from 'yup';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { Formik, Form, Field } from 'formik';
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
import { adaptFieldValue } from '../../../../../utils/String';
import { dateFormat, parse } from '../../../../../utils/Time';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RemediationEditionGeneral from './RemediationEditionGeneral';
import RequiredResources from './RequiredResources';
import RelatedTasks from './RelatedTasks';
import RemediationEditionDetails from './RemediationEditionDetails';

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

// const remediationEditionMutation = graphql`
//   mutation RemediationEditionContainerMutation(
//     $id: ID!,
//     $input: [EditInput]!
//   ) {
//     editRemediation(id: $id, input: $input) {
//       id
//     }
//   }
// `;

const riskValidation = () => Yup.object().shape({
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
class RemediationEditionContainer extends Component {
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

    const adaptedValues = R.evolve(
      {
        modified: () => parse(values.modified).format(),
        created: () => parse(values.created).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.assoc('name', values.name),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1])
      }))
    )(adaptedValues);
    // const pair = Object.keys(values).map((key) => [{ key, value: values[key] }]);
    commitMutation({
      // mutation: remediationEditionMutation,
      variables: {
        id: this.props.risk?.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: (err) => console.error(err),
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
      remediationId,
      risk,
      remediation,
    } = this.props;
    const remediationOriginData = R.pathOr([], ['origins', 0, 'origin_actors', 0, 'actor'], remediation);
    const initialValues = R.pipe(
      R.assoc('id', risk?.id || ''),
      R.assoc('description', risk?.description || ''),
      R.assoc('name', risk?.name || ''),
      R.assoc('source', remediationOriginData?.name || []),
      R.assoc('modified', dateFormat(risk?.modified)),
      R.assoc('created', dateFormat(risk?.created)),
      R.assoc('lifecycle', remediation?.lifecycle || []),
      R.assoc('responsible_type', remediation?.responsible_type || ''),
      R.pick([
        'id',
        'name',
        'description',
        'source',
        'modified',
        'created',
        'lifecycle',
        'response_type',
      ]),
    )(risk);
    // const { editContext } = risk;
    return (
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          // validationSchema={riskValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({
            submitForm,
            isSubmitting,
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
                    {/* <RiskEditionOverview
                      risk={risk}
                      enableReferences={this.props.enableReferences}
                      context={editContext}
                      handleClose={handleClose.bind(this)}
                    /> */}
                    <RemediationEditionGeneral
                      risk={risk}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <RemediationEditionDetails remediation={remediation} />
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
                  {/* <CyioCoreObjectAssetCreationExternalReferences /> */}
                  <RequiredResources remediationId={remediationId} />
                </Grid>
                <Grid item={true} xs={6}>
                  {/* <CyioCoreObjectLatestHistory /> */}
                  <RelatedTasks
                    toType='OscalTask'
                    fromType='RiskResponse'
                    remediationId={remediationId}
                  />
                </Grid>
              </Grid>
              <Grid
                container={true}
                spacing={3}
                classes={{ container: classes.gridContainer }}
                style={{ marginTop: 50 }}
              >
                <Grid item={true} xs={6}>
                  <CyioCoreObjectExternalReferences
                    externalReferences={risk.links}
                    fieldName='links'
                    cyioCoreObjectId={remediationId}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    notes={risk.remarks}
                    fieldName='remarks'
                    cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
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
                    onClick={() => this.props.history.push(`/activities/risk_assessment/risks/${this.props.riskId}/remediation`)}
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

RemediationEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  remediationId: PropTypes.string,
  risk: PropTypes.object,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
  riskId: PropTypes.string,
};

const RemediationEditionFragment = createFragmentContainer(
  RemediationEditionContainer,
  {
    risk: graphql`
      fragment RemediationEditionContainer_risk on RiskResponse {
        id
        name              # Title
        description       # Description
        created           # Created
        modified          # Last Modified
        lifecycle         # Lifecycle
        response_type     # Response Type
        links {
          id
          # created
          # modified
          external_id
          source_name
          description
          url
          media_type
        }
        remarks {
          id
          abstract
          content
          authors
        }
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
                name
              }
              ... on OscalParty {
                id
                party_type
                name      # source
              }
            }
          }
        }
        # ...RiskEditionOverview_risk
        # ...RiskEditionDetails_risk
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
)(RemediationEditionFragment);
