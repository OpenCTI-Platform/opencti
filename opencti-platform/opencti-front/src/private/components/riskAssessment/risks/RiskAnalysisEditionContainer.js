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
import RiskAnalysisEditionCharacterization from './RiskAnalysisEditionCharacterization';
import RiskAnalysisThreats from './RiskAnalysisThreats';

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

const riskAnalysisEditionMutation = graphql`
  mutation RiskAnalysisEditionContainerMutation(
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
class RiskAnalysisEditionContainer extends Component {
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
        deadline: () => parse(values.deadline).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    // const pair = Object.keys(values).map((key) => [{ key, value: values[key] }]);
    commitMutation({
      mutation: riskAnalysisEditionMutation,
      variables: {
        id: this.props.risk?.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
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
      riskId,
      handleClose,
      risk,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('id', risk?.id || ''),
      R.assoc('item_id', risk?.item_id || ''),
      R.assoc('description', risk?.description || ''),
      R.assoc('weakness', risk?.weakness || ''),
      R.assoc('controls', risk?.controls || ''),
      R.assoc('risk_rating', risk?.risk_rating || ''),
      R.assoc('priority', risk?.priority || ''),
      R.assoc('impact', risk?.impact || ''),
      R.assoc('likelihood', risk?.likelihood || ''),
      R.assoc('responsible_parties', risk?.responsible_parties || ''),
      R.assoc('labels', risk?.labels || []),
      R.assoc('name', risk?.name || ''),
      R.assoc('statement', risk?.statement || ''),
      R.assoc('risk_status', risk?.risk_status || ''),
      R.assoc('deadline', dateFormat(risk?.deadline)),
      R.assoc('impacted_component', risk?.impacted_component || ''),
      R.assoc('impacted_assets', risk?.impacted_assets || ''),
      R.assoc('detection_source', risk?.detection_source || ''),
      R.assoc('impacted_control', risk?.impacted_control || ''),
      R.assoc('false_positive', risk?.false_positive || ''),
      R.assoc('operationally_required', risk?.operationally_required || ''),
      R.assoc('risk_adjusted', risk?.risk_adjusted || ''),
      R.assoc('vendor_dependency', risk?.vendor_dependency || ''),
      R.pick([
        'id',
        // 'item_id',
        'description',
        // 'weakness',
        // 'controls',
        // 'risk_rating',
        'priority',
        // 'impact',
        // 'likelihood',
        // 'responsible_parties',
        'labels',
        'name',
        'statement',
        'risk_status',
        'deadline',
        // 'impacted_component',
        // 'impacted_assets',
        // 'detection_source',
        // 'impacted_control',
        'false_positive',
        // 'operationally_required',
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
                    <RiskAnalysisEditionCharacterization
                      risk={risk}
                    // enableReferences={this.props.enableReferences}
                    // context={editContext}
                    // handleClose={handleClose.bind(this)}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <RiskAnalysisThreats
                      risk={risk}
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
                    disableAdd={true}
                    externalReferences={risk.links}
                    fieldName='links'
                    cyioCoreObjectId={riskId}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk?.id} /> */}
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    disableAdd={true}
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

RiskAnalysisEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  risk: PropTypes.object,
  riskId: PropTypes.string,
  enableReferences: PropTypes.bool,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const RiskAnalysisEditionFragment = createFragmentContainer(
  RiskAnalysisEditionContainer,
  {
    risk: graphql`
      fragment RiskAnalysisEditionContainer_risk on POAMItem {
        id
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
        ...RiskAnalysisEditionCharacterization_risk
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
)(RiskAnalysisEditionFragment);
