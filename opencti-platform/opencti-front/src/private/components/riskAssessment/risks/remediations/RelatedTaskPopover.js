/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose,
  pathOr,
  mergeAll,
  map,
  path,
  pipe,
  dissoc,
  assoc,
} from 'ramda';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { withStyles } from '@material-ui/core/styles/index';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import AddIcon from '@material-ui/icons/Add';
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
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import DatePickerField from '../../../../../components/DatePickerField';
import environmentDarkLight from '../../../../../relay/environmentDarkLight';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { dateFormat } from '../../../../../utils/Time';
import SelectField from '../../../../../components/SelectField';
import { commitMutation, QueryRenderer } from '../../../../../relay/environment';
import CyioExternalReferenceEdition from '../../../analysis/external_references/CyioExternalReferenceEdition';
import Loader from '../../../../../components/Loader';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import MarkDownField from '../../../../../components/MarkDownField';

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
    externalReferenceEdit(id: $id) {
      delete
    }
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
      timings: {
        start_date: '',
        end_date: '',
      },
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
    console.log('relatedTask', values);
    this.setState({
      timings: {
        start_date: values.start_date,
        end_date: values.end_date,
      },
    });
    const finalValues = pipe(
      dissoc('start_date'),
      dissoc('end_date'),
      dissoc('responsible_role'),
      assoc('timings', this.state.timings),
      dissoc('timings'),
      // map((n) => ({
      //   'key': n[0],
      //   'value': n[1],
      // }))
    )(values);
    console.log('relatedTasksPopoverFinal', finalValues);
    // CM(environmentDarkLight, {
    //   mutation: relatedTaskEditionQuery,
    //   variables: {
    //     id: this.props.data.id,
    //     input: [
    //       { key: 'id', value: values.id },
    //       { key: 'name', value: values.name },
    //       { key: 'description', value: values.description },
    //       { key: 'subject_type', value: values.resource_type },
    //       { key: 'subject_ref', value: values.resource },
    //     ],
    //   },
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleCloseUpdate();
    //   },
    //   // onError: (err) => console.log('CyioNoteEditionDarkLightMutationError', err),
    // });
  }

  submitDelete() {
    this.setState({ deleting: true });
    CM(environmentDarkLight, {
      mutation: relatedTaskPopoverDeletionMutation,
      variables: {
        id: this.props.externalReferenceId,
      },
      onCompleted: (data) => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
      onError: (err) => console.log('ExtRefDeletionDarkLightMutationError', err),
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

  render() {
    const {
      classes,
      t,
      externalReferenceId,
      handleRemove,
      remediationId,
      refreshQuery,
      relatedTaskData,
      data,
    } = this.props;
    const taskDependency = pipe(
      pathOr([], ['task_dependencies']),
      mergeAll,
    )(data);
    const responsibleRoles = pipe(
      pathOr([], ['responsible_roles']),
      mergeAll,
      path(['role']),
    )(data);
    const initialValues = R.pipe(
      R.assoc('id', data?.id || ''),
      R.assoc('name', data?.name || ''),
      R.assoc('description', data?.description || ''),
      R.assoc('task_type', data?.task_type || ''),
      R.assoc('start_date', dateFormat(data.timing?.start_date) || dateFormat(data.timing?.on_date)),
      R.assoc('end_date', dateFormat(data?.timing?.end_date)),
      R.assoc('related_tasks', ''),
      R.assoc('associated_activities', ''),
      R.assoc('dependencies', taskDependency?.name || ''),
      R.assoc('responsible_parties', responsibleRoles.role_identifier || ''),
      R.pick([
        'id',
        'name',
        'description',
        'associated_activities',
        'related_tasks',
        'task_type',
        'start_date',
        'end_date',
        'dependencies',
        'responsible_parties',
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
          onClose={this.handleCloseUpdate.bind(this)}
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
          // onReset={this.onResetContextual.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Related Task')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
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
                        <Field
                          component={SelectField}
                          name="task_type"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        >
                          <MenuItem value='milestone'>
                            Milestone
                          </MenuItem>
                          <MenuItem value='action'>
                            Action
                          </MenuItem>
                          <MenuItem value='query'>
                            Query
                          </MenuItem>
                          <MenuItem value='list'>
                            List
                          </MenuItem>
                          <MenuItem value='ruke'>
                            Rule
                          </MenuItem>
                        </Field>
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
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Milestone')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 5px 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="Milestone"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        >
                          <MenuItem value='Helloworld'>
                            helloWorld
                          </MenuItem>
                          <MenuItem value='test'>
                            test
                          </MenuItem>
                          <MenuItem value='data'>
                            data
                          </MenuItem>
                        </Field>
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
                            {t('Dependency')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon style={{ margin: '0 0 4px 0' }} fontSize="small" />
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="dependencies"
                          fullWidth={true}
                          size="small"
                          variant='outlined'
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
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
                            {t('Related Tasks')}
                          </Typography>
                          <Tooltip style={{ margin: '0 0 4px 5px' }} title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                          <AddIcon style={{ margin: '0 0 4px 0' }} fontSize="small" />
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="related_tasks"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        >
                          <MenuItem value='Helloworld'>
                            helloWorld
                          </MenuItem>
                          <MenuItem value='test'>
                            test
                          </MenuItem>
                          <MenuItem value='data'>
                            data
                          </MenuItem>
                        </Field>
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
                          <AddIcon style={{ margin: '0 0 4px 0' }} fontSize="small" />
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="associated_activities"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid item={true} xs={12}>
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
                        <AddIcon style={{ margin: '0 0 4px 0' }} fontSize="small" />
                      </div>
                      <Field
                        component={SelectField}
                        style={{ height: '38.09px' }}
                        variant='outlined'
                        name="responsible_parties"
                        size='small'
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                      >
                        <MenuItem value='Helloworld'>
                          helloWorld
                        </MenuItem>
                        <MenuItem value='test'>
                          test
                        </MenuItem>
                        <MenuItem value='data'>
                          data
                        </MenuItem>
                      </Field>
                    </div>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid style={{ marginTop: '6px' }} xs={12} item={true}>
                      <CyioCoreObjectExternalReferences
                        refreshQuery={refreshQuery}
                        typename={relatedTaskData.__typename}
                        externalReferences={relatedTaskData.links}
                        cyioCoreObjectId={remediationId}
                      />
                    </Grid>
                    <Grid style={{ marginTop: '20px' }} xs={12} item={true}>
                      <CyioCoreObjectOrCyioCoreRelationshipNotes
                        refreshQuery={refreshQuery}
                        typename={relatedTaskData.__typename}
                        notes={relatedTaskData.remarks}
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
                    onClick={this.handleCloseUpdate.bind(this)}
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
  relatedTaskData: PropTypes.object,
  remediationId: PropTypes.string,
  externalReferenceId: PropTypes.string,
  refreshQuery: PropTypes.func,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  handleRemove: PropTypes.func,
  data: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(RelatedTaskPopover);
