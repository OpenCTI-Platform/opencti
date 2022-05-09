/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose,
  dissoc,
  assoc,
  evolve,
  pipe,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import Grid from '@material-ui/core/Grid';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import AddIcon from '@material-ui/icons/Add';
import MenuItem from '@material-ui/core/MenuItem';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import DatePickerField from '../../../../../components/DatePickerField';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/SelectField';
import MarkDownField from '../../../../../components/MarkDownField';
import { insertNode } from '../../../../../utils/Store';
import { parse } from '../../../../../utils/Time';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import TaskType from '../../../common/form/TaskType';
import RelatedTaskFields from '../../../common/form/RelatedTaskFields';
import ResourceType from '../../../common/form/ResourceType';
import AssociatedActivities from '../../../common/form/AssociatedActivities';
import ResponsibleParties from '../../../common/form/ResponsibleParties';
import Dependencies from '../../../common/form/Dependencies';
import ResourceNameField from '../../../common/form/ResourceNameField';
import ResourceTypeField from '../../../common/form/ResourceTypeField';
import { toastGenericError } from "../../../../../utils/bakedToast";

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  dialogRoot: {
    padding: '24px',
    overflowY: 'hidden',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    overflowY: 'scroll',
    height: '550px',
    padding: '0 24px',
    marginBottom: '24px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  createButtonContextual: {
    // position: 'fixed',
    // bottom: 30,
    // right: 30,
    zIndex: 3000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
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
});

const RelatedTaskCreationMutation = graphql`
  mutation RelatedTaskCreationMutation(
    $input: OscalTaskAddInput
  ) {
    createOscalTask(input: $input) {
      __typename
      id
    }
  }
`;

export const RelatedTaskCreationAddReferenceMutation = graphql`
  mutation RelatedTaskCreationAddReferenceMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

const RelatedTaskValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  // external_id: Yup.string(),
  // url: Yup.string().url(t('The value must be an URL')),
  task_type: Yup.string().required(t('This field is required')),
  description: Yup.string().required(t('This field is required')),
});

class RelatedTaskCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      close: false,
      resourceName: '',
      responsible_roles: [],
      associated_activities: [],
      timing: {},
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleResourceTypeFieldChange(resourceType) {
    this.setState({ resourceName: resourceType });
  }

  handleClose() {
    this.setState({ open: false, resourceName: '', fieldName: '' });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    if (values.responsible_roles.length > 0) {
      this.setState({
        responsible_roles: values.responsible_roles.map((value) => (
          { role: value }
        )),
      });
    }
    if (values.associated_activities.length > 0) {
      this.setState({
        associated_activities: values.associated_activities.map((value) => (
          { 'activity_id': value }
        )),
      });
    }
    if (values.start_date && values.end_date) {
      this.setState({
        timing: {
          within_date_range: {
            start_date: values.start_date === null ? null : parse(values.start_date),
            end_date: values.end_date === null ? null : parse(values.end_date),
          }
        },
      })
    }
    const finalValues = pipe(
      dissoc('start_date'),
      dissoc('end_date'),
      dissoc('resource_type'),
      dissoc('resource'),
      assoc('timing', this.state.timing),
      assoc('responsible_roles', this.state.responsible_roles),
    )(values);
    CM(environmentDarkLight, {
      mutation: RelatedTaskCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (response) => {
        this.handleAddReferenceMutation(response.createOscalTask);
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
      onError: (err) => {
        toastGenericError("Failed to create related task")
        console.error(err);
      }
    });
    // commitMutation({
    //   mutation: RelatedTaskCreationMutation,
    //   variables: {
    //     input: values,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_externalReferences',
    //     this.props.paginationOptions,
    //     'externalReferenceAdd',
    //   ),
    //   setSubmitting,
    //   onCompleted: (response) => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //     if (this.props.onCreate) {
    //       this.props.onCreate(response.externalReferenceAdd, true);
    //     }
    //   },
    // });
  }
  handleAddReferenceMutation(taskResponse) {
    CM(environmentDarkLight, {
      mutation: RelatedTaskCreationAddReferenceMutation,
      variables: {
        toId: taskResponse.id,
        fromId: this.props.remediationId,
        fieldName: 'tasks',
        to_type: 'OscalTask',
        from_type: 'RiskResponse',
      },
      onCompleted: () => {
        this.props.refreshQuery();
      },
      onError: (err) => {
        toastGenericError("Failed to Add related task")
        console.error(err);
      }
    });
  }

  onResetClassic() {
    this.handleClose();
  }

  handleCancelClick() {
    this.setState({
      open: false,
      close: true,
      resourceName: '',
      fieldName: '',
    });
  }

  handleCancelCloseClick() {
    this.setState({ close: false, resourceName: '', fieldName: '' });
  }

  onResetContextual() {
    this.handleClose();
  }

  renderClassic() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">
              {t('Create an external reference')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                source_name: '',
                external_id: '',
                url: '',
                description: '',
              }}
              // validationSchema={RelatedTaskValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="external_id"
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name="url"
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  }

  renderContextual() {
    const {
      t, classes, inputValue, refreshQuery, display, remediationId, relatedTaskData,
    } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <IconButton
          color="inherit"
          aria-label="Add"
          edge="end"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Dialog
          open={this.state.open}
          classes={{ root: classes.dialogRoot }}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
          maxWidth='sm'
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              name: '',
              description: '',
              task_type: '',
              start_date: null,
              end_date: null,
              task_dependencies: [],
              related_tasks: [],
              associated_activities: [],
              responsible_roles: [],
              resource_type: '',
              resource: '',
            }}
            validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onResetContextual.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Task')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="name"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                          invalidDateMessage={t(
                            'Field is required',
                          )}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          size="small"
                          style={{ float: 'left' }}
                        >
                          {t('ID')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('ID')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="id"
                          fullWidth={true}
                          disabled={true}
                          size="small"
                          variant='outlined'
                          containerstyle={{ width: '100%' }}
                        >
                          {this.props.remediationId}
                        </Field>
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Task Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 5px 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <TaskType
                          name="task_type"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Description')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Start Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="start_date"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('End Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="end_date"
                          fullWidth={true}
                          size="small"
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 5px 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <ResourceTypeField
                          name='resource_type'
                          fullWidth={true}
                          variant='outlined'
                          handleResourceType={this.handleResourceTypeFieldChange.bind(this)}
                          type='hardware'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 5px 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <ResourceNameField
                          name='resource'
                          resourceTypename={this.state.resourceName}
                          fullWidth={true}
                          variant='outlined'
                          type='hardware'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t(' Related Tasks')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Related Tasks')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <RelatedTaskFields
                          name="related_tasks"
                          fullWidth={true}
                          multiple={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Associated Activities ')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Associated Activities')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <RelatedTaskFields
                          name="associated_activities"
                          fullWidth={true}
                          multiple={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Responsible Parties')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Responsible Parties')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <RelatedTaskFields
                          name="responsible_roles"
                          fullWidth={true}
                          multiple={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Dependencies')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <RelatedTaskFields
                          name="task_dependencies"
                          fullWidth={true}
                          multiple={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid style={{ marginTop: '6px' }} xs={12} item={true}>
                      <CyioCoreObjectExternalReferences
                        refreshQuery={refreshQuery}
                        disableAdd={true}
                        fieldName='links'
                        typename='CyioExternalReference'
                        externalReferences={[]}
                        cyioCoreObjectId={remediationId}
                      />
                    </Grid>
                    <Grid style={{ marginTop: '15px' }} xs={12} item={true}>
                      <CyioCoreObjectOrCyioCoreRelationshipNotes
                        refreshQuery={refreshQuery}
                        disableAdd={true}
                        typename='CyioNotes'
                        notes={[]}
                        fieldName='remarks'
                        cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
                        marginTop="0px"
                      // data={props}
                      // marginTop={marginTop}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    // onClick={handleReset}
                    onClick={this.handleCancelClick.bind(this)}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          open={this.state.close}
          keepMounted={true}
          // TransitionComponent={Transition}
          onClose={this.handleCancelCloseClick.bind(this)}
        >
          <DialogContent>
            <Typography className={classes.popoverDialog} >
              {t('Are you sure you’d like to cancel?')}
            </Typography>
            <Typography align='left'>
              {t('Your progress will not be saved')}
            </Typography>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              // onClick={this.handleCloseDelete.bind(this)}
              // disabled={this.state.deleting}
              // onClick={handleReset}
              onClick={this.handleCancelCloseClick.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
              onClick={() => this.props.history.goBack()}
              color="secondary"
              // disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="contained"
              size="small"
            >
              {t('Yes, Cancel')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

RelatedTaskCreation.propTypes = {
  relatedTaskData: PropTypes.object,
  remediationId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  onCreate: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RelatedTaskCreation);
