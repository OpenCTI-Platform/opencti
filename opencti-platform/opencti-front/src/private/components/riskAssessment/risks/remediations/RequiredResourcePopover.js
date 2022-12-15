/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import {
  map,
  pipe,
  dissoc,
  assoc,
  toPairs,
} from 'ramda';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Grid from '@material-ui/core/Grid';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { adaptFieldValue } from '../../../../../utils/String';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import MarkDownField from '../../../../../components/MarkDownField';
import ResourceNameField from '../../../common/form/ResourceNameField';
import ResourceTypeField from '../../../common/form/ResourceTypeField';
import { toastGenericError } from '../../../../../utils/bakedToast';

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
    height: '500px',
    overflowX: 'hidden',
    padding: '8px 24px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  dialogClosebutton: {
    float: 'left',
    padding: '8px 0 24px 24px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: theme.palette.navAlt.background,
    },
  },
  resourceDropdown: {
    maxHeight: 130,
    overflow: 'auto',
    background: '#06102D',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const requiredResourcePopoverDeletionMutation = graphql`
  mutation RequiredResourcePopoverDeletionMutation($id: ID!, $remediationId: ID) {
    deleteRequiredAsset(id: $id, remediationId: $remediationId)
  }
`;

const requiredResourcePopoverEditionMutation = graphql`
  mutation RequiredResourcePopoverEditionQuery($id: ID!, $input: [EditInput]!) {
    editOscalResource(id: $id, input: $input) {
      id
    }
  }
`;

const RequiredResourcePopoverDataQuery = graphql`
 query RequiredResourcePopoverDataQuery{
  __type(name: "SubjectType") {
    name
    enumValues {
      name
      description
    }
  }
}
`;

class RequiredResourcePopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      resourceName: '',
      // subjects: [{
      //   subject_type: '',
      //   subject_ref: '',
      // }],
    };
  }

  componentDidMount() {
    const requiredResourceNode = R.pipe(
      R.pathOr([], ['subjects']),
      R.map((value) => ({
        resource_type: value.subject_type
      })),
      R.mergeAll,
    )(this.props.data);
    this.setState({ resourceName: requiredResourceNode.resource_type });
  }

  handleResourceTypeFieldChange(resourceType) {
    this.setState({ resourceName: resourceType });
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null, resourceName: '' });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
    this.handleClose();
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false, resourceName: '' });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false, resourceName: '' });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const subjects = (values.resource_type === '' && values.resource === '')
      ? []
      : [JSON.stringify({
        subject_type: values.resource_type,
        subject_ref: values.resource,
      })];

    const finalValues = pipe(
      dissoc('id'),
      dissoc('resource'),
      dissoc('resource_type'),
      assoc('subjects', subjects),
      toPairs,
      map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: requiredResourcePopoverEditionMutation,
      variables: {
        id: this.props.data.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data, error) => {
        if (error) {
          this.setState({ error });
        } else {
          setSubmitting(false);
          resetForm();
          this.handleCloseUpdate();
          this.props.refreshQuery();
        }
      },
      onError: (err) => {
        toastGenericError('Failed to update Required Resource');
        const ErrorResponse = JSON.parse(JSON.stringify(err.res.errors));
        this.setState({ error: ErrorResponse });
      },
    });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: requiredResourcePopoverDeletionMutation,
      variables: {
        id: this.props.requiredResourceId,
        remediationId: this.props.remediationId,
      },
      onCompleted: (data) => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
        this.props.refreshQuery();
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Failed to delete Required Resource');
      },
    });
    // commitMutation({
    //   mutation: requiredResourcePopoverDeletionMutation,
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
      refreshQuery,
      remediationId,
      data,
    } = this.props;
    const requiredResourceNode = R.pipe(
      R.pathOr([], ['subjects']),
      R.map((value) => ({
        resource_type: value.subject_type,
        resource: value.subject_ref.id,
      })),
      R.mergeAll,
    )(data);
    const initialValues = R.pipe(
      R.assoc('id', data.id || ''),
      R.assoc('name', data?.name || ''),
      R.assoc('description', data?.description || ''),
      R.assoc('resource_type', requiredResourceNode.resource_type || ''),
      R.assoc('resource', requiredResourceNode.resource || ''),
      R.pick([
        'id',
        'name',
        'description',
        'resource',
        'resource_type',
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
          fullWidth={true}
          maxWidth='sm'
        >
          {/* <QR
            environment={environmentDarkLight}
            query={cyioRequiredResourceEditionQuery}
            variables={{ id: externalReferenceId }}
            render={({ props }) => {
              if (props) {
                Done
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
            query={cyioRequiredResourceEditionQuery}
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
            // validationSchema={RequiredAssetValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Resource')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '15px' }}>
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
                      <div style={{ marginBottom: '15px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Type')} >
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
                      <div style={{ marginBottom: '15px' }}>
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
                      <div style={{ marginBottom: '15px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Resource Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Resource')} >
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
                    <Grid style={{ marginTop: '5px' }} xs={12} item={true}>
                      <CyioCoreObjectExternalReferences
                        typename={data.__typename}
                        fieldName='links'
                        externalReferences={data.links}
                        cyioCoreObjectId={remediationId}
                        refreshQuery={refreshQuery}
                      />
                    </Grid>
                    <Grid style={{ marginTop: '15px' }} xs={12} item={true}>
                      <CyioCoreObjectOrCyioCoreRelationshipNotes
                        typename={data.__typename}
                        notes={data.remarks}
                        fieldName='remarks'
                        cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
                        marginTop='0px'
                        refreshQuery={refreshQuery}
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
                    {t('Update')}
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

RequiredResourcePopover.propTypes = {
  remediationId: PropTypes.string,
  externalReferenceId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  history: PropTypes.object,
  t: PropTypes.func,
  handleRemove: PropTypes.func,
  refreshQuery: PropTypes.func,
  data: PropTypes.object,
  requiredResourceId: PropTypes.string,
};

export default R.compose(withRouter, inject18n, withStyles(styles))(RequiredResourcePopover);
