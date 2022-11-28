/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  evolve,
} from 'ramda';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
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
import { adaptFieldValue } from '../../../../utils/String';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { dateFormat } from '../../../../utils/Time';
import EntryType from '../../common/form/EntryType';
import RiskStatus from '../../common/form/RiskStatus';
import LoggedBy from '../../common/form/LoggedBy';
import { toastGenericError } from '../../../../utils/bakedToast';
import { commitMutation } from '../../../../relay/environment';

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
  mutation RiskTrackingPopoverDeletionMutation($id: ID!, $riskId: ID) {
    deleteRiskLogEntry(id: $id, riskId: $riskId)
  }
`;

const RiskTrackingEditionQuery = graphql`
  mutation RiskTrackingPopoverEditionQuery($id: ID!, $input: [EditInput]!) {
    editRiskLogEntry(id: $id, input: $input) {
      id
    }
  }
`;

class RiskTrackingPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayCancel: false,
      displayDelete: false,
      deleting: false,
      logged_by: [],
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

  handleCloseEditUpdate() {
    this.setState({ displayUpdate: false });
  }

  handleCloseUpdate() {
    this.setState({ displayCancel: true });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  handleBackButton() {
    this.setState({ displayCancel: false });
  }

  handleCancelButton() {
    this.setState({ displayCancel: false, displayUpdate: false });
  }

  onSubmit(values, { setSubmitting }) {
    const adaptedValues = evolve(
      {
        logged_by: () => values.logged_by.length > 0 && [JSON.stringify({ 'party': values.logged_by })],
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    commitMutation({
      mutation: RiskTrackingEditionQuery,
      variables: {
        id: this.props.node.id,
        input: finalValues,
      },
      setSubmitting,
      pathname: `/activities/risk_assessment/risks/${this.props.riskId}/tracking`,
      onCompleted: (data) => {
        setSubmitting(false);
        this.handleCloseEditUpdate();
        this.props.refreshQuery();
      },
      onError: () => {
        toastGenericError('Request Failed');
      },
    });

    // commitMutation({
    //   mutation: deviceEditionMutation,
    //   variables: {
    //     input: finalValues,
    //   },
    //   updater: (store) => insertNode(
    //     store,
    //     'Pagination_computingDeviceAssetList',
    //     this.props.paginationOptions,
    //     'editComputingDeviceAsset',
    //   ),
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: RiskTrackingPopoverDeletionMutation,
      variables: {
        id: this.props.node.id,
        riskId: this.props.riskId,
      },
      onCompleted: (data) => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
        this.props.refreshQuery();
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Request Failed');
      },
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

  onReset() {
    this.handleCloseUpdate();
  }

  render() {
    const {
      classes,
      t,
      handleRemove,
      node,
      riskStatusResponse,
    } = this.props;
    const riskTrackingLoggedBy = R.pipe(
      R.pathOr([], ['logged_by']),
      R.mergeAll,
    )(node);
    const initialValues = R.pipe(
      R.assoc('entry_type', node?.entry_type || []),
      R.assoc('name', node?.name || ''),
      R.assoc('description', node?.description || ''),
      R.assoc('event_start', dateFormat(node?.event_start)),
      R.assoc('event_end', dateFormat(node?.event_end)),
      R.assoc('logged_by', riskTrackingLoggedBy?.party?.id || []),
      R.assoc('status_change', node?.status_change || ''),
      R.assoc('related_responses', riskStatusResponse.map((value) => value.id) || []),
      R.pick([
        'entry_type',
        'name',
        'description',
        'event_start',
        'event_end',
        'logged_by',
        'status_change',
        'related_responses',
      ]),
    )(node);
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
            initialValues={initialValues}
            // validationSchema={riskValidation(t)}
            onReset={this.onReset.bind(this)}
            onSubmit={this.onSubmit.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('Risk Log Entry')}</DialogTitle>
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
                        <EntryType
                          variant='outlined'
                          name="entry_type"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px', marginBottom: '3px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
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
                          name="name"
                          fullWidth={true}
                          containerstyle={{ width: '100%' }}
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
                        component={MarkDownField}
                        name="description"
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        variant='outlined'
                      />
                    </Grid>
                  </Grid>
                  <Grid spacing={3} container={true}>
                    <Grid item={true} xs={6}>
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
                          name="event_start"
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
                        {/* <Field
                          component={SelectField}
                          variant='outlined'
                          name="logged_by"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '50%', padding: '0 0 1px 0' }}
                        /> */}
                        <LoggedBy
                          variant='outlined'
                          name="logged_by"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px', marginBottom: '3px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
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
                          component={SelectField}
                          name="related_responses"
                          fullWidth={true}
                          size="small"
                          multiple={true}
                          variant='outlined'
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        >
                          {riskStatusResponse.map((value, i) => (
                            value.name && <MenuItem value={value.id} key={i}>
                              {value.name}
                            </MenuItem>
                          ))}
                        </Field>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
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
                          name="event_end"
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
                        <RiskStatus
                          variant='outlined'
                          name="status_change"
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px', marginBottom: '3px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                      </div>
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions style={{ float: 'left', marginLeft: '15px', marginBottom: '20px' }}>
                  <Button
                    variant="outlined"
                    classes={{ root: classes.buttonPopover }}
                    onClick={handleReset}
                  // disabled={isSubmitting}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    classes={{ root: classes.buttonPopover }}
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Update')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <Dialog
          open={this.state.displayCancel}
          TransitionComponent={Transition}
        >
          <DialogContent>
            <Typography style={{
              fontSize: '18px',
              lineHeight: '24px',
              color: 'white',
            }} >
              {t('Are you sure you’d like to cancel?')}
            </Typography>
            <DialogContentText>
              {t('Your progress will not be saved')}
            </DialogContentText>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              // onClick={this.handleCloseDelete.bind(this)}
              // disabled={this.state.deleting}
              onClick={this.handleBackButton.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Go Back')}
            </Button>
            <Button
              // onClick={this.submitDelete.bind(this)}
              // disabled={this.state.deleting}
              onClick={() => this.handleCancelButton()}
              color="primary"
              classes={{ root: classes.buttonPopover }}
              variant="contained"
              size="small"
            >
              {t('Yes Cancel')}
            </Button>
          </DialogActions>
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

RiskTrackingPopover.propTypes = {
  externalReferenceId: PropTypes.string,
  paginationOptions: PropTypes.object,
  refreshQuery: PropTypes.func,
  riskId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  handleRemove: PropTypes.func,
  node: PropTypes.object,
  riskStatusResponse: PropTypes.array,
};
export default compose(inject18n, withStyles(styles))(RiskTrackingPopover);
