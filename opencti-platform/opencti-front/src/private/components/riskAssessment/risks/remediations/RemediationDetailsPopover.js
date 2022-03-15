import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import NoteAddIcon from '@material-ui/icons/NoteAdd';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import AddIcon from '@material-ui/icons/Add';
import { MoreVertOutlined } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import SelectField from '../../../../../components/SelectField';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
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

const remediationDetailsPopoverDeletionMutation = graphql`
  mutation RemediationDetailsPopoverDeletionMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

class RemediationDetailsPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      details: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
    this.handleClose();
  }

  handleCloseUpdate() {
    this.setState({ details: false });
  }

  handleOpenDetails() {
    this.setState({ details: true });
    this.handleClose();
  }

  handleCloseDetails() {
    this.setState({ details: false });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: remediationDetailsPopoverDeletionMutation,
      variables: {
        id: this.props.cyioCoreRelationshipId,
      },
      updater: (store) => {
        if (typeof this.props.onDelete !== 'function') {
          const container = store.getRoot();
          const payload = store.getRootField('stixCoreRelationshipEdit');
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            this.props.connectionKey || 'Pagination_stixCoreRelationships',
            this.props.paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
        }
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDetails();
        if (typeof this.props.onDelete === 'function') {
          this.props.onDelete();
        }
      },
    });
  }

  render() {
    const {
      classes, t, cyioCoreRelationshipId, disabled, risk, remediation,
    } = this.props;
    console.log('riskDetails', risk);
    console.log('remediationDetails', remediation);
    return (
      <span className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          disabled={disabled}
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
            onClick={this.handleOpenDetails.bind(this)}
          >
            {t('Details')}
          </MenuItem>
        </Menu>
        <Dialog
          open={this.state.details}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDetails.bind(this)}
        >
          <Formik
            enableReinitialize={true}
          // initialValues={initialValues}
          // validationSchema={RelatedTaskValidation(t)}
          // onSubmit={this.onSubmit.bind(this)}
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
                          {t('Created')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="created"
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
                          {t('Last Modified')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Description')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={DatePickerField}
                          name="modified"
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
                      <Grid xs={12} style={{ marginTop: '10px' }} item={true}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Description')}
                        </Typography>
                        <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                          <Tooltip title={t('Label')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="description"
                          fullWidth={true}
                          multiline={true}
                          rows="4"
                          variant='outlined'
                        />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Grid style={{ marginBottom: '20px' }} item={true}>
                        <Typography variant="h3"
                          color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                          {t('Source')}
                        </Typography>
                        <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                          <Tooltip title={t('Source')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <AddIcon fontSize="small" style={{ margin: '-4px 0 0 0' }} />
                        <div className="clearfix" />
                        <div>
                          <Field
                            component={SelectField}
                            variant='outlined'
                            name="source"
                            size='small'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                          />
                          <Field
                            component={SelectField}
                            variant='outlined'
                            name="source"
                            size='small'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                          />
                        </div>
                      </Grid>
                      <Grid style={{ marginBottom: '15px' }} item={true}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Response Type')}
                        </Typography>
                        <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                          <Tooltip
                            title={t(
                              'Response type',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="response_type"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                      </Grid>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Grid style={{ marginTop: '80px' }} item={true}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Lifecycle')}
                        </Typography>
                        <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                          <Tooltip
                            title={t(
                              'Lifecycle',
                            )}
                          >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="lifecycle"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                      </Grid>
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
      </span>
    );
  }
}

RemediationDetailsPopover.propTypes = {
  cyioCoreRelationshipId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onDelete: PropTypes.func,
  connectionKey: PropTypes.string,
  risk: PropTypes.object,
  remediation: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RemediationDetailsPopover);
