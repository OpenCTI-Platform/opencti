/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
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
import Slide from '@material-ui/core/Slide';
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

const remediationEditionMutation = graphql`
  mutation RemediationDetailsPopoverMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editRiskResponse(id: $id, input: $input) {
      id
    }
  }
`;

class RemediationDetailsPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      details: false,
      close: false,
      onSubmit: false,
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
    this.handleClose();
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const sourceValues = R.pickAll(['actor_ref', 'actor_type'], values);

    const adaptedValues = R.evolve(
      {
        modified: () => values.modified === null ? null : parse(values.modified).format(),
        created: () => values.created === null ? null : parse(values.created).format(),
      },
      values,
    );
    const finalValues = R.pipe(
      R.dissoc('actor_type'),
      R.dissoc('actor_ref'),
      R.assoc('origins', JSON.stringify([{ origin_actors: [sourceValues] }])),
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(adaptedValues);
    commitMutation({
      mutation: remediationEditionMutation,
      variables: {
        id: this.props.cyioCoreRelationshipId,
        input: finalValues,
      },
      setSubmitting,
      pathname: `/activities/risk_assessment/risks/${this.props.riskId}/remediation`,
      onCompleted: (data, error) => {
        if (error) {
          this.setState({ error });
        } else {
          setSubmitting(false);
          this.handleClose();
          this.props.history.push(`/activities/risk_assessment/risks/${this.props.riskId}/remediation`);
        }
      },
      onError: (err) => {
        toastGenericError('Request Failed');
      },
    });
    this.setState({ onSubmit: true });
  }

  render() {
    const {
      classes,
      t,
      remediation,
    } = this.props;
    const SourceOfDetection = R.pipe(
      R.pathOr([], ['origins']),
      R.mergeAll,
      R.path(['origin_actors']),
      R.mergeAll,
    )(remediation);
    const initialValues = R.pipe(
      R.assoc('name', remediation?.name || ''),
      R.assoc('description', remediation?.description || ''),
      R.assoc('actor_type', SourceOfDetection.actor_type || ''),
      R.assoc('actor_ref', SourceOfDetection.actor_ref?.id || ''),
      // R.assoc('modified', dateFormat(remediation?.modified)),
      // R.assoc('created', dateFormat(remediation?.created)),
      R.assoc('lifecycle', remediation?.lifecycle || []),
      R.assoc('response_type', remediation?.response_type || ''),
      R.pick([
        'name',
        'created',
        'modified',
        'actor_ref',
        'lifecycle',
        'actor_type',
        'description',
        'response_type',
      ]),
    )(remediation);
    return (
      <>
        <Dialog
          open={this.props.displayEdit}
          keepMounted={true}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            // validationSchema={RelatedTaskValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Edit Remediation')}</DialogTitle>
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
                          <Tooltip title={t('Name')} >
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
                  {/* <Grid container={true} spacing={3}>
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
                          <Tooltip title={t('Created')} >
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
                          <Tooltip title={t('Last Modified')} >
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
                  </Grid> */}
                  <Grid container={true} spacing={3}>
                    <Grid xs={12} item={true}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Description')}
                      </Typography>
                      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                        <Tooltip title={t('Description')}>
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
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Grid style={{ marginTop: '10px', marginBottom: '20px' }} item={true}>
                        <Typography variant="h3"
                          color="textSecondary" gutterBottom={true} style={{ float: 'left' }}>
                          {t('Source')}
                        </Typography>
                        <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
                          <Tooltip title={t('Source')}>
                            <Information fontSize="inherit" color="disabled" />
                          </Tooltip>
                        </div>
                        <div className="clearfix" />
                        <Source
                          variant='outlined'
                          values={values}
                          setFieldValue={setFieldValue}
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '50%', padding: '0 0 12px 0' }}
                        />
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
                        <ResponseType
                          variant='outlined'
                          name='response_type'
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                      </Grid>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Grid style={{ marginTop: '97px' }} item={true}>
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
                        <RiskLifeCyclePhase
                          variant='outlined'
                          name='lifecycle'
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
                    onClick={this.handleCancelOpenClick.bind(this)}
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
              //onClick={() => this.props.history.push(`/activities/risk_assessment/risks/${this.props.riskId}/remediation`)}
              onClick={() => {
                this.setState({ close: false });
                this.props.handleCloseEdit();
              }}
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

RemediationDetailsPopover.propTypes = {
  cyioCoreRelationshipId: PropTypes.string,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
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
  handleCloseEdit: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RemediationDetailsPopover);
