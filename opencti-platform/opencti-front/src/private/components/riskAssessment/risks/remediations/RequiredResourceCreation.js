/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose,
  dissoc,
  assoc,
  pipe,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResourceNameField from '../../../common/form/ResourceNameField';
import ResourceTypeField from '../../../common/form/ResourceTypeField';
import { toastGenericError } from '../../../../../utils/bakedToast';

const styles = (theme) => ({
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: theme.palette.navAlt.background,
    },
  },
  drawerPaper: {
    minHeight: '100%',
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
    height: '500px',
    overflowX: 'hidden',
    padding: '8px 24px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  dialogClosebutton: {
    float: 'left',
    padding: '8px 0 24px 24px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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

const RequiredResourceCreationMutation = graphql`
  mutation RequiredResourceCreationMutation($input: RequiredAssetAddInput) {
    createRequiredAsset(input: $input) {
      id
      name
      description
    }
  }
`;

const RequiredResourceValidation = (t) =>
  Yup.object().shape({
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().required(t('This field is required')),
  });

class RequiredResourceCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      close: false,
      resourceName: '',
      selectedIndex: 1,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleResourceTypeFieldChange(resourceType) {
    this.setState({ resourceName: resourceType });
  }

  handleClose() {
    this.setState({ open: false, resourceName: '' });
  }

  handleCancelClick() {
    this.setState({
      close: true,
      resourceName: '',
    });
  }

  handleCancelCloseClick() {
    this.setState({ close: false, resourceName: '' });
  }

  onSubmit(values, { setSubmitting }) {
    const subjects = (values.resource_type === '' && values.resource === '')
      ? []
      : [{
        subject_type: values.resource_type,
        subject_ref: values.resource,
      }];
    const finalValues = pipe(
      dissoc('resource_type'),
      dissoc('resource'),
      assoc('remediation_id', this.props.remediationId),
      assoc('subjects', subjects),
    )(values);
    commitMutation({
      mutation: RequiredResourceCreationMutation,
      variables: {
        input: finalValues,
      },
      // updater: (store) => insertNode(
      //   store,
      //   'Pagination_externalReferences',
      //   this.props.paginationOptions,
      //   'externalReferenceAdd',
      // ),
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        this.handleClose();
        this.props.refreshQuery();
        if (this.props.onCreate) {
          this.props.onCreate(response.externalReferenceAdd, true);
        }
      },
      onError: () => {
        toastGenericError('Failed to create Required Resource');
      },
    });
    // commitMutation({
    //   mutation: RequiredResourceCreationMutation,
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

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    this.handleCancelClick();
  }

  renderClassic() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color='secondary'
          aria-label='Add'
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor='right'
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label='Close'
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize='small' />
            </IconButton>
            <Typography variant='h6'>{t('Required Asset')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                resource_type: '',
                resource: '',
              }}
              validationSchema={RequiredResourceValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name='source_name'
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name='external_id'
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name='url'
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={MarkDownField}
                    name='description'
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows='4'
                    style={{ marginTop: 20 }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant='contained'
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant='contained'
                      color='primary'
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Submit')}
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
      t,
      classes,
      refreshQuery,
      display,
      remediationId,
    } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <IconButton
          color='inherit'
          aria-label='Add'
          edge='end'
          style={{ marginTop: '-15px' }}
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize='small' />
        </IconButton>
        <Dialog
          open={this.state.open}
          classes={{ root: classes.dialogRoot }}
          fullWidth={true}
          maxWidth='sm'
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              name: '',
              resource: '',
              description: '',
              resource_type: '',
            }}
            validationSchema={RequiredResourceValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onResetContextual.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('Resource')}
                </DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Name')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Description')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      <Field
                        component={TextField}
                        name='name'
                        fullWidth={true}
                        size='small'
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6} style={{ marginBottom: '15px' }}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Resource Type')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Resource Type')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      <ResourceTypeField
                        name='resource_type'
                        fullWidth={true}
                        variant='outlined'
                        handleResourceType={this.handleResourceTypeFieldChange.bind(this)}
                        type='hardware'
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={6} style={{ marginBottom: '15px' }}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Resource Name')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Resource')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      <ResourceNameField
                        name='resource'
                        resourceTypename={this.state.resourceName}
                        fullWidth={true}
                        variant='outlined'
                        type='hardware'
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Description')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
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
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant='outlined'
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant='contained'
                    color='primary'
                    onClick={submitForm}
                    classes={{ root: classes.buttonPopover }}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
          <Dialog
            open={this.state.close}
            keepMounted={true}
          // TransitionComponent={Transition}
          >
            <DialogContent>
              <Typography className={classes.popoverDialog}>
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
                variant='outlined'
                size='small'
              >
                {t('Go Back')}
              </Button>
              <Button
                onClick={() => this.props.history.goBack()}
                color='secondary'
                // disabled={this.state.deleting}
                classes={{ root: classes.buttonPopover }}
                variant='contained'
                size='small'
              >
                {t('Yes, Cancel')}
              </Button>
            </DialogActions>
          </Dialog>
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

RequiredResourceCreation.propTypes = {
  requiredResourceData: PropTypes.object,
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
)(RequiredResourceCreation);
