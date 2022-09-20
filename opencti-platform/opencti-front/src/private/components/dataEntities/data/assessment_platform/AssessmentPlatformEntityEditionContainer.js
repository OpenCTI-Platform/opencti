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
import { dateFormat, parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import SelectField from '../../../../../components/SelectField';
import TextField from '../../../../../components/TextField';
import DatePickerField from '../../../../../components/DatePickerField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from "../../../../../utils/bakedToast";


const styles = (theme) => ({
  dialogMain: {
    overflowY: 'hidden',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'scroll',
    height: '650px',
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

const assessmentPlatformEntityEditionContainerMutation = graphql`
  mutation AssessmentPlatformEntityEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editAssessmentPlatform(id: $id, input: $input) {
      id
    }
  }
`;

class AssessmentPlatformEntityEditionContainer extends Component {
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

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = R.evolve(
      {
        modified: () => values.modified === null ? null : parse(values.modified).format(),
        created: () => values.created === null ? null : parse(values.created).format(),
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
      mutation: assessmentPlatformEntityEditionContainerMutation,
      variables: {
        id: this.props.cyioCoreRelationshipId,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Request Failed');
      }
    });
    this.setState({ onSubmit: true });
  }

  render() {
    const {
      classes,
      t,
      assessmentPlatform,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', assessmentPlatform?.name || ''),
      R.assoc('description', assessmentPlatform?.description || ''),
      R.assoc('modified', dateFormat(assessmentPlatform?.modified)),
      R.assoc('created', dateFormat(assessmentPlatform?.created)),
      R.pick([
        'name',
        'description',
        'modified',
        'created',
      ]),
    )(assessmentPlatform);
    return (
      <>
        <Dialog
          open={this.props.displayEdit}
          keepMounted={true}
          className={classes.dialogMain}
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
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Assessment Platform')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Id')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Id')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name="id"
                        disabled={true}
                        fullWidth={true}
                        size="small"
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
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
                          {t('Created Date')}
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
                          disabled={true}
                          containerstyle={{ width: '100%' }}
                          variant='outlined'
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          style={{ height: '38.09px' }}
                        />
                      </div>
                      <div style={{ marginBottom: '12px' }}>
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
                    <Grid item={true} xs={6}>
                      <div style={{ marginBottom: '10px' }}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ float: 'left' }}
                        >
                          {t('Modified Date')}
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
                          disabled={true}
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
                        name='description'
                        fullWidth={true}
                        multiline={true}
                        rows='3'
                        variant='outlined'
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('User Component(s)')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('User Component(s)')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <div style={{ display: 'grid', gridTemplateColumns: '35% 1fr' }}>
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="user"
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                        <Field
                          component={SelectField}
                          variant='outlined'
                          name="user_component"
                          fullWidth={true}
                          style={{ height: '38.09px' }}
                          containerstyle={{ width: '100%' }}
                        />
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Marking')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Marking')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="marking"
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    // onClick={handleReset}
                    onClick={() => this.props.handleDisplayEdit()}
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
      </>
    );
  }
}

AssessmentPlatformEntityEditionContainer.propTypes = {
  assessmentPlatform: PropTypes.object,
  handleDisplayEdit: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
  enableReferences: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AssessmentPlatformEntityEditionContainer);
