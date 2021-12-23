import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
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
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import DatePickerField from '../../../../components/DatePickerField';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import MarkDownField from '../../../../components/MarkDownField';
import { insertNode } from '../../../../utils/Store';

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
  },
  dialogContent: {
    overflowY: 'hidden',
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
  buttonPopover: {
    textTransform: 'capitalize',
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

const RiskLogCreationMutation = graphql`
  mutation RiskLogCreationMutation(
    $input: ExternalReferenceAddInput!
  ) {
    externalReferenceAdd(input: $input) {
      id
      source_name
      description
      url
      external_id
      created
    }
  }
`;

const RiskLogValidation = (t) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string(),
  url: Yup.string().url(t('The value must be an URL')),
  description: Yup.string(),
});

class RiskLogCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    CM(environmentDarkLight, {
      mutation: RiskLogCreationMutation,
      variables: {
        input: values,
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
        resetForm();
        this.handleClose();
        if (this.props.onCreate) {
          this.props.onCreate(response.externalReferenceAdd, true);
        }
      },
      onError: (err) => console.log('ExternalReferenceCreationMutationError', err),
    });
    // commitMutation({
    //   mutation: RiskLogCreationMutation,
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
              validationSchema={RiskLogValidation(t)}
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
      t, classes, inputValue, display,
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
          PaperProps={{
            style: {
              overflowY: 'hidden',
              height: '570px',
            },
          }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              source_name: inputValue,
              external_id: '',
              url: '',
              description: '',
            }}
            validationSchema={RiskLogValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onResetContextual.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('New Risk Log')}</DialogTitle>
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
                          {t('Entry Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="entry_type"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginBottom: '15px' }}>
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
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                      <div style={{ marginBottom: '18px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Logged By')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="logged_by"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '50%' }}
                        />
                        <Field
                          component={SelectField}
                          name="logged_by"
                          fullWidth={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '50%' }}
                        />
                      </div>
                      <div style={{ marginBottom: '15px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Related Response')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 3px 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="related_response"
                          fullWidth={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
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
                          {t('Title')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="title"
                          fullWidth={true}
                          size="small"
                          variant='outlined'
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginBottom: '15px' }}>
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
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                          variant='outlined'
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                      <div style={{ marginBottom: '15px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Status Change')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          name="status_change"
                          fullWidth={true}
                          size="small"
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12} style={{ marginBottom: '15px' }}>
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
                        component={TextField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="3"
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions style={{ float: 'left', marginLeft: '15px', marginBottom: '20px' }}>
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
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          // open={this.state.displayDelete}
          keepMounted={true}
        // TransitionComponent={Transition}
        // onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <Typography className={classes.popoverDialog} >
              {t('Are you sure you’d like to delete this item?')}
            </Typography>
            <DialogContent>
              {t('This action can’t be undone')}
            </DialogContent>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              // onClick={this.handleCloseDelete.bind(this)}
              // disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
              // onClick={this.submitDelete.bind(this)}
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

RiskLogCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  onCreate: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RiskLogCreation);
