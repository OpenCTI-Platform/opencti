import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import { commitMutation as CM } from 'react-relay';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import { ConnectionHandler } from 'relay-runtime';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import inject18n from '../../../../components/i18n';
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
    margin: '10px 0',
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
  menuItem: {
    padding: '15px 0',
    width: '170px',
    margin: '0 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskAssessmentPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayPoamId: false,
      deleting: false,
      displayRiskLevel: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  onPoamSubmit(values, { setSubmitting, resetForm }) {
    CM(environmentDarkLight, {
      // mutation: RelatedTaskCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.handleClosePoam();
      },
      onError: (err) => console.log('riskPoamMutationError', err),
    });
  }

  onRiskLevelSubmit(values, { setSubmitting, resetForm }) {
    CM(environmentDarkLight, {
      // mutation: RelatedTaskCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.handleCloseRiskLevel();
      },
      onError: (err) => console.log('riskLevelMutationError', err),
    });
  }

  handleOpenPoam() {
    this.setState({ displayPoamId: true });
    this.handleClose();
  }

  handleClosePoam() {
    this.setState({ displayPoamId: false });
  }

  onResetPoam() {
    this.handleClosePoam();
  }

  onResetRiskLevel() {
    this.handleCloseRiskLevel();
  }

  handleOpenRiskLevel() {
    this.setState({ displayRiskLevel: true });
    this.handleClose();
  }

  handleCloseRiskLevel() {
    this.setState({ displayRiskLevel: false });
  }

  render() {
    const {
      classes, t, history, nodeId,
    } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
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
            onClick={() => history.push(`/dashboard/risk-assessment/risks/${nodeId}`)}
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
            className={classes.menuItem}
            onClick={this.handleOpenRiskLevel.bind(this)}
          >
            {t('Change Risk Level')}
          </MenuItem>
        </Menu>
        <Dialog
          maxWidth='sm'
          fullWidth={true}
          keepMounted={true}
          open={this.state.displayPoamId}
          TransitionComponent={Transition}
          classes={{ root: classes.dialogRoot }}
          onClose={this.handleClosePoam.bind(this)}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              poamId: '',
            }}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onPoamSubmit.bind(this)}
            onReset={this.onResetPoam.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>
                  {t('Assign POAM ID')}
                </DialogTitle>
                <DialogContent>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('POAM ID')}
                  </Typography>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    name="poamId"
                    fullWidth={true}
                    size="small"
                    containerstyle={{ width: '100%' }}
                    variant='outlined'
                  />
                </DialogContent>
                <DialogActions className={classes.dialogActions}>
                  <Button
                    onClick={this.handleClosePoam.bind(this)}
                    disabled={this.state.deleting}
                    classes={{ root: classes.buttonPopover }}
                    variant="outlined"
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    // onClick={this.submitDelete.bind(this)}
                    color="primary"
                    onClick={submitForm}
                    classes={{ root: classes.buttonPopover }}
                    variant="contained"
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
          onClose={this.handleCloseRiskLevel.bind(this)}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              risk_level: '',
            }}
          // validationSchema={RelatedTaskValidation(t)}
          onSubmit={this.onRiskLevelSubmit.bind(this)}
          onReset={this.onResetRiskLevel.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ padding: '10px 15px 20px 5px' }}>
                <DialogTitle>
                  {t('Risk Level')}
                </DialogTitle>
                <Grid
                  style={{
                    display: 'flex',
                    alignItems: 'end',
                  }}
                  container={true}
                >
                  <DialogContent>
                    <Field
                      component={SelectField}
                      name="risk_level"
                      fullWidth={true}
                      size="small"
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                      MenuProps={{
                        anchorOrigin: {
                          vertical: 'bottom',
                          horizontal: 'left',
                        },
                        getContentAnchorEl: null,
                      }}
                    >
                      <MenuItem value='very-low'>
                        Very Low
                      </MenuItem>
                      <MenuItem value='low'>
                        Low
                      </MenuItem>
                      <MenuItem value='moderate'>
                        Moderate
                      </MenuItem>
                      <MenuItem value='high'>
                        High
                      </MenuItem>
                      <MenuItem value='very-high'>
                        Very High
                      </MenuItem>
                    </Field>
                  </DialogContent>
                  <DialogActions className={classes.dialogRiskLevelAction}>
                    <Button
                      onClick={this.handleCloseRiskLevel.bind(this)}
                      disabled={this.state.deleting}
                      classes={{ root: classes.buttonPopover }}
                      variant="outlined"
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      // onClick={this.submitDelete.bind(this)}
                      color="primary"
                      onClick={submitForm}
                      classes={{ root: classes.buttonPopover }}
                      variant="contained"
                    >
                      {t('Submit')}
                    </Button>
                  </DialogActions>
                </Grid>
              </Form>
            )}
          </Formik>
        </Dialog>
      </div>
    );
  }
}

RiskAssessmentPopover.propTypes = {
  nodeId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RiskAssessmentPopover);
