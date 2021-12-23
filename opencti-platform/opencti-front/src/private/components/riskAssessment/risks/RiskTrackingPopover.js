import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Grid from '@material-ui/core/Grid';
import { Formik, Form, Field } from 'formik';
import { Information } from 'mdi-material-ui';
import Button from '@material-ui/core/Button';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
// import CyioExternalReferenceEdition from './CyioExternalReferenceEdition';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  // drawerPaper: {
  //   width: '50%',
  //   position: 'fixed',
  //   overflow: 'auto',
  //   backgroundColor: theme.palette.background.paper,
  //   transition: theme.transitions.create('width', {
  //     easing: theme.transitions.easing.sharp,
  //     duration: theme.transitions.duration.enteringScreen,
  //   }),
  //   padding: 0,
  // },
  dialogRoot: {
    padding: '24px',
  },
  dialogContent: {
    overflowY: 'hidden',
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
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

const RiskTrackingPopoverDeletionMutation = graphql`
  mutation RiskTrackingPopoverDeletionMutation($id: ID!) {
    externalReferenceEdit(id: $id) {
      delete
    }
  }
`;

const RiskTrackingEditionQuery = graphql`
  query RiskTrackingPopoverEditionQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEdition_externalReference
    }
  }
`;

class RiskTrackingPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
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

  submitDelete() {
    this.setState({ deleting: true });
    CM(environmentDarkLight, {
      mutation: RiskTrackingPopoverDeletionMutation,
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
    //   mutation: RiskTrackingPopoverDeletionMutation,
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
      handleOpenUpdate,
    } = this.props;
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
          // classes={{ paper: classes.drawerPaper }}
          fullWidth={true}
          maxWidth='sm'
          classes={{ root: classes.dialogRoot }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          {/* <QR
            environment={environmentDarkLight}
            query={RiskTrackingEditionQuery}
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
            query={RiskTrackingEditionQuery}
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
          // initialValues={initialValues}
          // validationSchema={riskValidation(t)}
          // onSubmit={this.onSubmit.bind(this)}
          >
            <Form>
              <DialogTitle>{t('Risk Log')}</DialogTitle>
              <DialogContent classes={{ root: classes.dialogContent }}>
                <Grid spacing={3} container={true}>
                  <Grid item={true} xs={6}>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Entry Type')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="entry_type"
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px', marginBottom: '3px' }}
                        containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                      />
                    </div>
                    <div style={{ marginBottom: '20px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Start Date')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={DatePickerField}
                        variant='outlined'
                        size='small'
                        name="start_date"
                        fullWidth={true}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Logged By')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="logged_by"
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                      />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="logged_by"
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Related Response')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        variant='outlined'
                        size='small'
                        name="related_response"
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                      />
                    </div>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <div style={{ marginBottom: '20px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Title')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        variant='outlined'
                        size='small'
                        name="title"
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                      />
                    </div>
                    <div style={{ marginBottom: '20px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('End Date')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={DatePickerField}
                        variant='outlined'
                        size='small'
                        name="end_date"
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        style={{ height: '38.09px' }}
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                      />
                    </div>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography
                        variant="subtitle2"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Status Change')}
                      </Typography>
                      <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                        <Tooltip
                          title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                        >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="status_change"
                        size='small'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                      />
                    </div>
                  </Grid>
                </Grid>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={12}>
                    <Typography
                      variant="subtitle2"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Description')}
                    </Typography>
                    <div style={{ float: 'left', margin: '0 0 0 4px' }}>
                      <Tooltip
                        title='In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.'
                      >
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
              </DialogContent>
              <DialogActions style={{ float: 'left', marginLeft: '15px', marginBottom: '20px' }}>
                <Button
                  variant="outlined"
                  classes={{ root: classes.buttonPopover }}
                  onClick={this.handleCloseUpdate.bind(this)}
                // disabled={isSubmitting}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  classes={{ root: classes.buttonPopover }}
                // onClick={submitForm}
                // disabled={isSubmitting}
                >
                  {t('Update')}
                </Button>
              </DialogActions>
            </Form>
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

RiskTrackingPopover.propTypes = {
  externalReferenceId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  handleRemove: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RiskTrackingPopover);
