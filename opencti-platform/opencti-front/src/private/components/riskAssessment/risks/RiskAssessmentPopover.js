/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import { adaptFieldValue } from '../../../../utils/String';
import TextField from '../../../../components/TextField';
import DatePickerField from '../../../../components/DatePickerField';
import inject18n from '../../../../components/i18n';
import RiskStatus from '../../common/form/RiskStatus';
import { toastGenericError } from "../../../../utils/bakedToast";
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    margin: '20px 0 10px 0',
    padding: '10px 0 20px 22px',
  },
  dialogRiskLevelAction: {
    textAlign: 'right',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogRoot: {
    padding: '24px',
  },
  dialogContent: {
    overflowY: 'hidden',
  },
  menuItem: {
    padding: '15px 0',
    width: '170px',
    margin: '0 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction='up' ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const riskAssessmentPopoverEditMutation = graphql`
  mutation RiskAssessmentPopoverEditMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editRisk(id: $id, input: $input) {
      id
    }
  }
`;

class RiskAssessmentPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      isOpen: false,
      anchorEl: null,
      deleting: false,
      displayPoamId: false,
      displayRiskLevel: false,
      displayRiskDeadline: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget, isOpen: true });
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  onPoamSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.assoc('poam_id', values.poam_id),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: riskAssessmentPopoverEditMutation,
      variables: {
        id: this.props.node.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.handleClosePoam();
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError("Failed to fetch Risk");
      }
    });
  }

  onRiskLevelSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.assoc('risk_status', values.risk_status),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: riskAssessmentPopoverEditMutation,
      variables: {
        id: this.props.node.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseRiskLevel();
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError("Failed to fetch Risk");
      }
    });
  }

  onRiskDeadlineSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': [adaptFieldValue(n[1])],
      })),
    )(values);
    commitMutation({
      mutation: riskAssessmentPopoverEditMutation,
      variables: {
        id: this.props.nodeId,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseRiskDeadline();
        this.props.history.push('/activities/risk_assessment/risks');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError("Failed to fetch Risk");
      }
    });
  }

  handleOpenPoam() {
    this.setState({ displayPoamId: true, isOpen: true });
    this.handleClose();
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleClosePoam() {
    this.setState({ displayPoamId: false, isOpen: false });
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  onResetPoam() {
    this.handleClosePoam();
  }

  onResetRiskDeadline() {
    this.handleCloseRiskDeadline();
  }

  onResetRiskLevel() {
    this.handleCloseRiskLevel();
  }

  handleOpenRiskLevel() {
    this.setState({ displayRiskLevel: true, isOpen: true });
    this.handleClose();
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleOpenRiskDeadline() {
    this.setState({ displayRiskDeadline: true, isOpen: true });
    this.handleClose();
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleCloseRiskLevel() {
    this.setState({ displayRiskLevel: false, isOpen: false });
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  handleCloseRiskDeadline() {
    this.setState({ displayRiskDeadline: false, isOpen: false });
    if (this.props.handleOpenMenu) {
      this.props.handleOpenMenu(this.state.isOpen);
    }
  }

  render() {
    const {
      classes,
      t,
      history,
      nodeId,
    } = this.props;
    return (
      <div className={classes.container}>
        <IconButton onClick={this.handleOpen.bind(this)} aria-haspopup='true'>
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
            onClick={() => history.push(`/activities/risk_assessment/risks/${nodeId}`)}
          >
            {t('Details')}
          </MenuItem>
          <MenuItem
            className={classes.menuItem}
            onClick={this.handleOpenPoam.bind(this)}
            divider={true}
          >
            {t('Assign POAM ID')}
          </MenuItem>
          <MenuItem
            divider={true}
            className={classes.menuItem}
            onClick={this.handleOpenRiskLevel.bind(this)}
          >
            {t('Change Risk Status')}
          </MenuItem>
          <MenuItem
            className={classes.menuItem}
            onClick={this.handleOpenRiskDeadline.bind(this)}
          >
            {t('Assign Risk Deadline')}
          </MenuItem>
        </Menu>
        <Dialog
          maxWidth='sm'
          fullWidth={true}
          keepMounted={true}
          open={this.state.displayPoamId}
          TransitionComponent={Transition}
          classes={{ root: classes.dialogRoot }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              poam_id: this.props.node.poam_id,
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onPoamSubmit.bind(this)}
            onReset={this.onResetPoam.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('Assign POAM ID')}</DialogTitle>
                <DialogContent>
                  <Typography
                    variant='h3'
                    color='textSecondary'
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('POAM ID')}
                  </Typography>
                  <div className='clearfix' />
                  <Field
                    component={TextField}
                    name='poam_id'
                    fullWidth={true}
                    size='small'
                    containerstyle={{ width: '100%' }}
                    variant='outlined'
                  />
                </DialogContent>
                <DialogActions className={classes.dialogActions}>
                  <Button
                    onClick={handleReset}
                    disabled={this.state.deleting}
                    classes={{ root: classes.buttonPopover }}
                    variant='outlined'
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    // onClick={this.submitDelete.bind(this)}
                    color='primary'
                    onClick={submitForm}
                    classes={{ root: classes.buttonPopover }}
                    variant='contained'
                    disabled={isSubmitting}
                  >
                    {t('Submit')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          fullWidth={true}
          open={this.state.displayRiskLevel}
          TransitionComponent={Transition}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              risk_status: this.props.node.risk_status,
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onRiskLevelSubmit.bind(this)}
            onReset={this.onResetRiskLevel.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ padding: '10px 15px 20px 5px' }}>
                <DialogTitle>{t('Risk Status')}</DialogTitle>
                <Grid
                  style={{
                    display: 'flex',
                    alignItems: 'initial',
                  }}
                  container={true}
                >
                  <DialogContent classes={{ root: classes.dialogContent }}>
                    <RiskStatus
                      variant='outlined'
                      name='risk_status'
                      size='small'
                      fullWidth={true}
                      style={{ height: '38.09px', marginBottom: '3px' }}
                      containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                    />
                  </DialogContent>
                  <DialogActions style={{ marginTop: '6px' }} className={classes.dialogRiskLevelAction}>
                    <Button
                      onClick={handleReset}
                      disabled={this.state.deleting}
                      classes={{ root: classes.buttonPopover }}
                      variant='outlined'
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      // onClick={this.submitDelete.bind(this)}
                      color='primary'
                      onClick={submitForm}
                      classes={{ root: classes.buttonPopover }}
                      variant='contained'
                      disabled={isSubmitting}
                    >
                      {t('Submit')}
                    </Button>
                  </DialogActions>
                </Grid>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          maxWidth='sm'
          fullWidth={true}
          keepMounted={true}
          open={this.state.displayRiskDeadline}
          TransitionComponent={Transition}
          classes={{ root: classes.dialogRoot }}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              deadline: this.props.node.deadline,
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onRiskDeadlineSubmit.bind(this)}
            onReset={this.onResetRiskDeadline.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('Assign Risk Deadline')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={DatePickerField}
                    name="deadline"
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ overflowY: 'hidden', padding: '10px 0' }}
                  />
                </DialogContent>
                <DialogActions className={classes.dialogActions}>
                  <Button
                    size='small'
                    variant='outlined'
                    onClick={handleReset}
                    disabled={this.state.deleting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    size='small'
                    color='primary'
                    variant='contained'
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
      </div>
    );
  }
}

RiskAssessmentPopover.propTypes = {
  node: PropTypes.object,
  riskNode: PropTypes.object,
  nodeId: PropTypes.string,
  handleOpenMenu: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RiskAssessmentPopover);
