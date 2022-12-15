/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import {
  compose,
  pipe,
  dissoc,
  assoc,
} from 'ramda';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import DialogActions from '@material-ui/core/DialogActions';
import graphql from 'babel-plugin-relay/macro';
import { dayStartDate, parse } from '../../../../../utils/Time';
import { commitMutation, QueryRenderer } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import SelectField from '../../../../../components/SelectField';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
import MarkDownField from '../../../../../components/MarkDownField';
import { toastGenericError } from '../../../../../utils/bakedToast';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import TaskType from '../../../common/form/TaskType';
import RelatedTaskFields from '../../../common/form/RelatedTaskFields';
import ResourceType from '../../../common/form/ResourceType';
import AssociatedActivities from '../../../common/form/AssociatedActivities';
import ResponsibleParties from '../../../common/form/ResponsibleParties';
import Dependencies from '../../../common/form/Dependencies';
import ResourceNameField from '../../../common/form/ResourceNameField';
import ResourceTypeField from '../../../common/form/ResourceTypeField';

const styles = (theme) => ({
  dialogMain: {
    overflow: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  dialogContent: {
    padding: '0 24px',
    overflow: 'scroll',
    height: '650px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const entitiesTasksCreationMutation = graphql`
  mutation EntitiesTasksCreationMutation($input: OscalTaskAddInput) {
    createOscalTask (input: $input) {
      id
    }
  }
`;

const taskValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().required(t('This field is required')),
  task_type: Yup.string().required(t('This field is required')),
  resource: Yup.array().when('resource_type', {
    is: (resource_type) => resource_type.length > 0,
    then: Yup.array().nullable().min(1, 'This field is required'),
  }),
  end_date: Yup.date()
  .when("start_date", {
    is: (start_date) => start_date === null,
    then: Yup.date().nullable().min(
      Yup.ref('start_date'),
      "End date can't be before start date")
  }),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';
class EntitiesTasksCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      onSubmit: false,
      displayCancel: false,
      resourceName: '',
      responsible_roles: [],
      associated_activities: [],
      timing: {},
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

  handleResourceTypeFieldChange(resourceType) {
    this.setState({ resourceName: resourceType });
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
          },
        },
      });
    }
    const finalValues = pipe(
      dissoc('start_date'),
      dissoc('end_date'),
      dissoc('resource_type'),
      dissoc('resource'),
      assoc('timing', this.state.timing),
      assoc('responsible_roles', this.state.responsible_roles),
    )(values);
    commitMutation({
      mutation: entitiesTasksCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      pathname: '/data/entities/tasks',
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        this.props.history.push('/data/entities/tasks');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Failed to create task');
      },
    });
    // commitMutation({
    //   mutation: entitiesTasksCreationMutation,
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
    this.setState({ open: false, resourceName: '', fieldName: '' });
  }

  handleSubmit() {
    this.setState({ onSubmit: true });
  }

  onReset() {
    this.handleClose();
    this.props.handleTaskCreation();
  }

  render() {
    const {
      t,
      classes,
      task,
      openDataCreation,
      handleTaskCreation,
      open,
      history,
    } = this.props;
    return (
      <>
        <Dialog
          open={openDataCreation}
          keepMounted={true}
          className={classes.dialogMain}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              name: '',
              description: '',
              task_type: '',
              associated_activities: [],
              related_tasks: [],
              subjects: [],
              start_date: null,
              end_date: null,
              resource_type: [],
              resource: [],
              responsible_roles: [],
              task_dependencies: [],
            }}
            validationSchema={taskValidation(t)}
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
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Task')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Name')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Name')} >
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
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Id')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Id')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="id"
                        disabled={true}
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Task Type')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Task Type')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <TaskType
                        name="task_type"
                        taskType='OscalTaskType'
                        fullWidth={true}
                        required={true}
                        variant='outlined'
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Description')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={MarkDownField}
                        name='description'
                        fullWidth={true}
                        multiline={true}
                        rows='3'
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
                          <Tooltip title={t('Start')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Resource Type')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Related Tasks')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Related Tasks')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Responsible Parties')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Responsible Parties')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
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
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('End Date')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('End Date')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Resource Name')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Associated Activities')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Associated Activities')} >
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
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Dependencies')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Dependencies')} >
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
                    {task && (
                      <>
                        <Grid item={true} xs={12}>
                          <CyioCoreObjectExternalReferences
                            typename={task.__typename}
                            externalReferences={task.links}
                            fieldName='links'
                            disableAdd={true}
                            cyioCoreObjectId={task?.id}
                          // refreshQuery={refreshQuery}
                          />
                        </Grid>
                        <Grid item={true} xs={12}>
                          <CyioCoreObjectOrCyioCoreRelationshipNotes
                            typename={task.__typename}
                            notes={task.remarks}
                            // refreshQuery={refreshQuery}
                            fieldName='remarks'
                            disableAdd={true}
                            marginTop='20px'
                            cyioCoreObjectOrCyioCoreRelationshipId={task?.id}
                          />
                        </Grid>
                      </>
                    )}
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
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
                    {t('Submit')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    );
  }
}

EntitiesTasksCreation.propTypes = {
  openDataCreation: PropTypes.bool,
  handleTaskCreation: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  task: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(EntitiesTasksCreation);
