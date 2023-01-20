/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
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
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from "../../../../../utils/bakedToast";
import DatePickerField from '../../../../../components/DatePickerField';
import TaskType from '../../../common/form/TaskType';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = (theme) => ({
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

class DataSourceDataUsageRestrictionsPopoverComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      close: false,
    };
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  handleCloseMain() {
    this.setState({ close: false });
    this.props.handleCloseDataUsageRestrictions();
  }

  render() {
    const {
      t,
      classes,
      dataSource,
      refreshQuery,
    } = this.props;
    const DataUsageRestrict = dataSource.iep;
    const initialValues = R.pipe(
      R.assoc('id', DataUsageRestrict?.id || ''),
      R.assoc('name', DataUsageRestrict?.name || ''),
      R.assoc('start_date', DataUsageRestrict?.start_date || ''),
      R.assoc('end_date', DataUsageRestrict?.end_date || ''),
      R.assoc('tlp', DataUsageRestrict?.tlp || ''),
      R.assoc('description', DataUsageRestrict?.description || ''),
      R.assoc('permitted_actions', DataUsageRestrict?.permitted_actions || ''),
      R.assoc('affected_party_notifications', DataUsageRestrict?.affected_party_notifications || ''),
      R.pick([
        'id',
        'tlp',
        'name',
        'end_date',
        'start_date',
        'description',
        'permitted_actions',
        'unmodified_resale',
        'encrypt_in_transit',
        'affected_party_notifications',
      ]),
    )(DataUsageRestrict);
    return (
      <>
        <Dialog
          open={this.props.openDataUsageRestrictions}
          keepMounted={true}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>
                  {t('Information Exchange Policy')}
                </DialogTitle>
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
                          {t('ID')}
                        </Typography>
                        <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                          <Tooltip title={t('Name')} >
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Field
                          component={TextField}
                          name="id"
                          fullWidth={true}
                          disabled={true}
                          size="small"
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                        />
                      </div>
                    </Grid>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Name')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Description')}>
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="name"
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography variant="h3"
                        color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Source')}>
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
                    <Grid container item={true} spacing={3}>
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
                            <Tooltip title={t('Start')} >
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
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('End Date')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('End')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <Field
                            component={DatePickerField}
                            name="end_date"
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
                    </Grid>
                    <Grid container item={true} spacing={3}>
                      <Grid item={true} xs={6}>
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Encrypt In Transit')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('Resource Type')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <TaskType
                            name='encrypt_in_transit'
                            taskType='EncryptInTransit'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '100%' }}
                            variant='outlined'
                          />
                        </div>
                      </Grid>
                      <Grid item={true} xs={6}>
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Permitted Actions')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('Resource Type')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <TaskType
                            name='permitted_actions'
                            taskType='PermittedActions'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '100%' }}
                            variant='outlined'
                          />
                        </div>
                      </Grid>
                    </Grid>
                    <Grid container item={true} spacing={3}>
                      <Grid item={true} xs={6}>
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Affected Party Notifications')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('Resource Type')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <TaskType
                            name='affected_party_notifications'
                            taskType='AffectedPartyNotifications'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '100%' }}
                            variant='outlined'
                          />
                        </div>
                      </Grid>
                      <Grid item={true} xs={6}>
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('TLP')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('Resource Type')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <TaskType
                            name='tlp'
                            taskType='TLPLevel'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '100%' }}
                            variant='outlined'
                          />
                        </div>
                      </Grid>
                    </Grid>
                    <Grid container item={true} spacing={3}>
                      <Grid item={true} xs={6}>
                        <div style={{ marginBottom: '12px' }}>
                          <Typography
                            variant="h3"
                            color="textSecondary"
                            gutterBottom={true}
                            style={{ float: 'left' }}
                          >
                            {t('Unmodified Resale')}
                          </Typography>
                          <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                            <Tooltip title={t('Resource Type')} >
                              <Information fontSize="inherit" color="disabled" />
                            </Tooltip>
                          </div>
                          <div className="clearfix" />
                          <TaskType
                            name='unmodified_resale'
                            taskType='UnmodifiedResale'
                            fullWidth={true}
                            style={{ height: '38.09px' }}
                            containerstyle={{ width: '100%' }}
                            variant='outlined'
                          />
                        </div>
                      </Grid>
                      <Grid item={true} xs={12}>
                        <CyioCoreObjectExternalReferences
                          typename={DataUsageRestrict.__typename}
                          externalReferences={DataUsageRestrict?.external_references}
                          fieldName='external_references'
                          cyioCoreObjectId={DataUsageRestrict?.id}
                          refreshQuery={refreshQuery}
                        />
                      </Grid>
                      <Grid item={true} xs={12}>
                        <CyioCoreObjectOrCyioCoreRelationshipNotes
                          typename={DataUsageRestrict.__typename}
                          notes={DataUsageRestrict.notes}
                          refreshQuery={refreshQuery}
                          fieldName='notes'
                          marginTop='20px'
                          cyioCoreObjectOrCyioCoreRelationshipId={DataUsageRestrict?.id}
                        />
                      </Grid>
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    onClick={this.handleCancelOpenClick.bind(this)}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    // onClick={submitForm}
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
              onClick={this.handleCancelCloseClick.bind(this)}
              classes={{ root: classes.buttonPopover }}
              variant='outlined'
              size='small'
            >
              {t('Go Back')}
            </Button>
            <Button
              onClick={this.handleCloseMain.bind(this)}
              color='secondary'
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

DataSourceDataUsageRestrictionsPopoverComponent.propTypes = {
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  classes: PropTypes.object,
  openDataUsageRestrictions: PropTypes.bool,
  handleCloseDataUsageRestrictions: PropTypes.func,
};

const DataSourceDataUsageRestrictionsPopover = createFragmentContainer(
  DataSourceDataUsageRestrictionsPopoverComponent,
  {
    dataSource: graphql`
      fragment DataSourceDataUsageRestrictionsPopover_dataSource on DataSource {
        iep {
          id
          name
          tlp
          color
          created
          modified
          end_date
          start_date
          description
          attribution
          iep_version
          entity_type
          definition_type
          permitted_actions
          unmodified_resale
          encrypt_in_transit
          affected_party_notifications
          external_references {
            __typename
            id
            source_name
            description
            entity_type
            url
            hashes {
              value
            }
            external_id
          }
          notes {
            __typename
            id
            entity_type
            abstract
            content
            authors
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceDataUsageRestrictionsPopover);