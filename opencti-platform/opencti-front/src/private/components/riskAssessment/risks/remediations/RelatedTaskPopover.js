/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withRouter } from 'react-router-dom';
import {
  compose,
  evolve,
  map,
  pipe,
  dissoc,
  assoc,
  toPairs,
} from 'ramda';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Grid from '@material-ui/core/Grid';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import DatePickerField from '../../../../../components/DatePickerField';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { dateFormat, parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import MarkDownField from '../../../../../components/MarkDownField';
import TaskType from '../../../common/form/TaskType';
import RelatedTaskFields from '../../../common/form/RelatedTaskFields';
import { toastGenericError } from '../../../../../utils/bakedToast';
import { commitMutation } from '../../../../../relay/environment';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.background.paper,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
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
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const relatedTaskPopoverDeletionMutation = graphql`
  mutation RelatedTaskPopoverDeletionMutation($id: ID!) {
    deleteOscalTask(id: $id)
  }
`;

const relatedTaskEditionQuery = graphql`
  mutation RelatedTaskPopoverEditionQuery($id: ID!, $input: [EditInput]!) {
    editOscalTask(id: $id, input: $input) {
      id
    }
  }
`;

class RelatedTaskPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      timing: {},
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
    this.handleClose();
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = evolve(
      {
        associated_activities: () => {
          if (values.associated_activities.length > 0) {
            values.associated_activities.map((value) => (
              JSON.stringify({ 'activity_id': value })
            ))
          } else {
            return []
          }
        },
      },
      values,
    );
    const timing = {
      within_date_range: {
        start_date: values.start_date === null ? null : parse(values.start_date),
        end_date: values.end_date === null ? null : parse(values.end_date),
      }
    }
    const finalValues = pipe(
      dissoc('start_date'),
      dissoc('end_date'),
      assoc('timings', JSON.stringify(timing)),
      toPairs,
      map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    commitMutation({
      mutation: relatedTaskEditionQuery,
      variables: {
        id: this.props.data.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseUpdate();
        this.props.refreshQuery();
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Failed to update Related Task');
      },
    });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: relatedTaskPopoverDeletionMutation,
      variables: {
        id: this.props.relatedTaskId,
      },
      onCompleted: (data, error) => {
        if (error) {
          this.setState({ error });
        } else {
          this.setState({ deleting: false });
          this.handleCloseDelete();
          this.props.refreshQuery();
        }
      },
      onError: (err) => {
        toastGenericError('Failed to delete Related Task');
        const ErrorResponse = JSON.parse(JSON.stringify(err.res.errors));
        this.setState({ error: ErrorResponse });
      },
    });
    // commitMutation({
    //   mutation: relatedTaskPopoverDeletionMutation,
    //   variables: {
    //     id: this.props.externalReferenceId,
    //   },
    //   updater: (store) => {
    //     const container = store.getRoot();
    //     const payload = store.getRootField('externalReferenceEdit');
    //     const userProxy = store.get(container.getDataID());
    //     const conn = ConnectionHandler.getConnection(
    //       userProxy,
    //       'Pagination_externalReferences',
    //       this.props.paginationOptions,
    //     );
    //     ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
    //   },
    //   onCompleted: () => {
    //     this.setState({ deleting: false });
    //     this.handleCloseDelete();
    //   },
    // });
  }

  onReset() {
    this.handleCloseUpdate();
  }

  render() {
    const {
      classes,
      t,
      handleRemove,
      remediationId,
      refreshQuery,
      data,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('id', data?.id || ''),
      R.assoc('name', data?.name || ''),
      R.assoc('description', data?.description || ''),
      R.assoc('task_type', data?.task_type || ''),
      R.assoc('start_date', dateFormat(data.timing?.start_date) || dateFormat(data.timing?.on_date)),
      R.assoc('end_date', dateFormat(data?.timing?.end_date)),
      R.assoc('related_tasks', []),
      R.assoc('associated_activities', []),
      R.assoc('task_dependencies', data.task_dependencies.map((value) => value.name) || []),
      R.assoc('responsible_roles', data.responsible_roles.map((value) => value.name) || []),
      R.pick([
        'id',
        'name',
        'description',
        'associated_activities',
        'related_tasks',
        'task_type',
        'start_date',
        'end_date',
        'task_dependencies',
        'responsible_roles',
      ]),
    )(data);
    return (
      <span className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 1 }}
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          <MenuItem
            className={classes.menuItem}
            divider={true}
            onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          {handleRemove && (
            <MenuItem
              onClick={() => {
                handleRemove();
                this.handleClose();
              }}
              divider={true}
              className={classes.menuItem}
            >
              {t('Remove')}
            </MenuItem>
          )}
          <MenuItem className={classes.menuItem} onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Dialog
          open={this.state.displayUpdate}
          keepMounted={true}
          classes={{ paper: classes.drawerPaper }}
        >
          {/* <QR
            environment={environmentDarkLight}
            query={relatedTaskEditionQuery}
            variables={{ id: externalReferenceId }}
            render={({ props }) => {
              if (props) {
                // Done
                return (
                  <CyioExternalReferenceEdition
                    externalReference={props.externalReference}
                    handleClose={this.handleCloseUpdate.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          /> */}
          {/* <QueryRenderer
            query={relatedTaskEditionQuery}
            variables={{ id: externalReferenceId }}
            render={({ props }) => {
              if (props) {
                // Done
                return (
                  <CyioExternalReferenceEdition
                    externalReference={props.externalReference}
                    handleClose={this.handleCloseUpdate.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          /> */}
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
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
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="id"
                          fullWidth={true}
                          size="small"
                          variant='outlined'
                          containerstyle={{ width: '100%' }}
                          disabled={true}
                        />
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
                          taskType='OscalTaskType'
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
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Related Task')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Associated Activities')} >
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
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Responsible Parties')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
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
                        fieldName='links'
                        typename='CyioExternalReference'
                        externalReferences={[]}
                        cyioCoreObjectId={remediationId}
                      />
                    </Grid>
                    <Grid style={{ marginTop: '20px' }} xs={12} item={true}>
                      <CyioCoreObjectOrCyioCoreRelationshipNotes
                        refreshQuery={refreshQuery}
                        fieldName='remarks'
                        typename='CyioNotes'
                        notes={[]}
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
                    onClick={handleReset}
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
                    {t('Submit')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <Typography className={classes.popoverDialog} >
              {t('Are you sure you’d like to delete this item?')}
            </Typography>
            <DialogContentText>
              {t('This action can’t be undone')}
            </DialogContentText>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitDelete.bind(this)}
              color="secondary"
              disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="contained"
              size="small"
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </span>
    );
  }
}

RelatedTaskPopover.propTypes = {
  remediationId: PropTypes.string,
  externalReferenceId: PropTypes.string,
  refreshQuery: PropTypes.func,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  handleRemove: PropTypes.func,
  data: PropTypes.object,
  relatedTaskId: PropTypes.string,
};

export default compose(withRouter, inject18n, withStyles(styles))(RelatedTaskPopover);
