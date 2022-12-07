/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import * as Yup from 'yup';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import { IconButton } from '@material-ui/core';
import { Add } from '@material-ui/icons';
import Slide from '@material-ui/core/Slide';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
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
    padding: '0 24px',
    marginBottom: '24px',
    overflow: 'hidden',
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

const remediationCreationMutation = graphql`
  mutation RemediationCreationMutation($input: RiskResponseAddInput) {
    createRiskResponse(input: $input) {
      id
    }
  }
`;

const remediationValidation = (t) =>
  Yup.object().shape({
    name: Yup.string().required(t('This field is required')),
    actor_type: Yup.string().required(t('This field is required')),
    actor_ref: Yup.string().required(t('This field is required')),
    response_type: Yup.string().required(t('This field is required')),
    lifecycle: Yup.string().required(t('This field is required')),
  });

class RemediationCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      details: false,
      close: false,
      onSubmit: false,
      open: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleSubmit() {
    this.setState({ onSumbit: true });
  }

  onReset() {
    this.handleCancelOpenClick();
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelClose() {
    this.setState({ close: false });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
    this.props.handleOpenCreation();
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.pickAll(['actor_ref', 'actor_type'], values);

    const finalValues = R.pipe(
      R.dissoc('created'),
      R.dissoc('modified'),
      R.dissoc('actor_ref'),
      R.dissoc('actor_target'),
      R.dissoc('actor_type'),
      R.dissoc('oscal_type'),
      R.dissoc('oscal_party'),
      R.assoc('origins', [{ origin_actors: [adaptedValues] }])
    )(values);

    commitMutation({
      mutation: remediationCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      pathname: `/activities/risk_assessment/risks/${this.props.riskId}/remediation`,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleCancelCloseClick();
        this.props.refreshQuery();
        this.props.history.push(`/activities/risk_assessment/risks/${this.props.riskId}/remediation`);
      },
      onError: (err) => {
        toastGenericError('Failed to create Remediation');
      },
    });
    this.setState({ onSubmit: true });
  }

  handleCreation(event) {
    this.setState({ openCreation: event.currentTarget });
  }

  handleOpenCreation() {
    this.setState({ openCreation: false });
  }

  render() {
    const {
      classes,
      t,
      history,
      riskId,
      location,
      remediationId
    } = this.props;
    return (
      <>
      {!location.pathname.includes(`/activities/risk_assessment/risks/${riskId}/remediation/${remediationId}`) 
        && <IconButton
              color="default"
              aria-label="Label"
              edge="end"
              onClick={this.props.handleCreation.bind(this)}
              style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            >
              <Add fontSize="small" />
            </IconButton>}
        <Dialog
          open={this.props.openCreation}
          keepMounted={true}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              risk_id: riskId,
              response_type: '',
              lifecycle: '',
              name: '',
              description: '',
              created: null,
              modified: null,
              actor_type: '',
              actor_ref: '',
            }}
            validationSchema={remediationValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              isSubmitting,
              setFieldValue,
              values,
              handleReset,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('New Remediation')}
                </DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant='h3'
                          color='textSecondary'
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Name')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Name')}>
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
                      </div>
                    </Grid>
                  </Grid>
                  {/* <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '12px' }}>
                        <Typography
                          variant='h3'
                          color='textSecondary'
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Created')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Created')}>
                            <Information fontSize='inherit' color='disabled' />
                          </Tooltip>
                        </div>
                        <div className='clearfix' />
                        <Field
                          component={DatePickerField}
                          name='created'
                          fullWidth={true}
                          size='small'
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)'
                          )}
                          style={{ height: '38.09px' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant='h3'
                          color='textSecondary'
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Last Modified')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Last Modified')}>
                            <Information fontSize='inherit' color='disabled' />
                          </Tooltip>
                        </div>
                        <div className='clearfix' />
                        <Field
                          component={DatePickerField}
                          name='modified'
                          fullWidth={true}
                          size='small'
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)'
                          )}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                  </Grid> */}
                  <Grid container={true} spacing={3}>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
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
                        rows='4'
                        variant='outlined'
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid
                      style={{ marginTop: '10px', marginBottom: '20px' }}
                      item={true}
                      xs={6}
                    >
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Source')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Source')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      {this.props.openCreation && <Source
                        variant='outlined'
                        values={values}
                        setFieldValue={setFieldValue}
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '50%', padding: '0 0 12px 0' }}
                      />}
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid style={{ marginBottom: '15px' }} item={true} xs={6}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Response Type')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip title={t('Response type')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      {this.props.openCreation && <ResponseType
                        variant='outlined'
                        name='response_type'
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                      />}
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant='h3'
                        color='textSecondary'
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Lifecycle')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip title={t('Lifecycle')}>
                          <Information fontSize='inherit' color='disabled' />
                        </Tooltip>
                      </div>
                      <div className='clearfix' />
                      {this.props.openCreation && <RiskLifeCyclePhase
                        variant='outlined'
                        name='lifecycle'
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                      />}
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant='outlined'
                    // onClick={handleReset}
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
              onClick={this.handleCancelClose.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant='outlined'
              size='small'
            >
              {t('Go Back')}
            </Button>
            <Button
              onClick={this.handleCancelCloseClick.bind(this)}
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
      </>
    );
  }
}

RemediationCreation.propTypes = {
  cyioCoreRelationshipId: PropTypes.string,
  handleDisplayEdit: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  location: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onDelete: PropTypes.func,
  connectionKey: PropTypes.string,
  enableReferences: PropTypes.bool,
  risk: PropTypes.object,
  riskId: PropTypes.string,
  remediation: PropTypes.object,
  remediationId: PropTypes.string,
  openCreation: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(RemediationCreation);
