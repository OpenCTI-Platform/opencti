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
import MenuItem from '@material-ui/core/MenuItem';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { adaptFieldValue } from '../../../../../utils/String';
import SelectField from '../../../../../components/SelectField';
import SwitchField from '../../../../../components/SwitchField';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import { toastGenericError } from "../../../../../utils/bakedToast";
import TaskType from '../../../common/form/TaskType';
import ScopeField from '../../../common/form/ScopeField';
import DataUsageRestrictionField from '../../../common/form/DataUsageRestrictionField';

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
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
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

const dataSourceEditionContainerMutation = graphql`
  mutation DataSourceEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editDataSource(id: $id, input: $input) {
      id
    }
  }
`;

const DataSourceEditionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class DataSourceEditionContainer extends Component {
  constructor(props) {
    super(props);
  }

  onReset() {
    this.props.handleDisplayEdit();
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    // const adaptedValues = R.evolve(
    //   {
    //     modified: () => values.modified === null ? null : parse(values.modified).format(),
    //     created: () => values.created === null ? null : parse(values.created).format(),
    //   },
    //   values,
    // );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: dataSourceEditionContainerMutation,
      variables: {
        id: this.props.dataSource.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.props.history.push(`/data/data_source/${this.props.dataSource.id}`);
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Request Failed');
      }
    });
  }

  render() {
    const {
      classes,
      t,
      disabled,
      dataSource,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('name', dataSource?.name || ''),
      R.assoc('auto', dataSource?.auto || ''),
      R.assoc('scope', dataSource?.scope || []),
      R.assoc('contextual', dataSource?.contextual || ''),
      R.assoc('description', dataSource?.description || ''),
      R.assoc('unit', dataSource?.update_frequency?.unit || ''),
      R.assoc('period', dataSource?.update_frequency?.period || 0),
      R.assoc('data_source_type', dataSource.data_source_type || ''),
      R.assoc('iep', dataSource.iep || ''),
      R.pick([
        'unit',
        'name',
        'description',
        'period',
        'contextual',
        'data_source_type',
        'auto',
        'scope',
        'iep'
      ]),
    )(dataSource);
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
            validationSchema={DataSourceEditionValidation(t)}
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
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('Data Source')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
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
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Data Source Type')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Data Source Type')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <TaskType
                        component={SelectField}
                        variant='outlined'
                        name='data_source_type'
                        taskType='DataSourceType'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
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
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Every')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Every')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={TextField}
                        name='period'
                        type='number'
                        fullWidth={true}
                        size='small'
                        containerstyle={{ width: '100%' }}
                        variant='outlined'
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Update Frequency')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Update Frequency')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <TaskType
                        component={SelectField}
                        variant='outlined'
                        name='unit'
                        taskType='TimeUnit'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Contextual')}
                        </Typography>
                        <Tooltip title={t('Contextual')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className={classes.textBase}>
                        <Field
                          component={SwitchField}
                          type="checkbox"
                          name="contextual"
                          containerstyle={{ marginLeft: 10, marginRight: '-15px' }}
                          inputProps={{ 'aria-label': 'ant design' }}
                        />
                        <Typography>Only Contextual</Typography>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Trigger')}
                        </Typography>
                        <Tooltip title={t('Trigger')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <Field
                        component={SelectField}
                        variant='outlined'
                        name="auto"
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                      >
                        <MenuItem value={''}>
                          <em>None</em>
                        </MenuItem>
                        <MenuItem value={true}>
                          {t('True')}
                        </MenuItem>
                        <MenuItem value={false}>
                          {t('False')}
                        </MenuItem>
                      </Field>
                    </Grid>
                    <Grid item={true} xs={12}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Data Usage Restriction')}
                      </Typography>
                      <div style={{ float: 'left', margin: '1px 0 0 5px' }}>
                        <Tooltip title={t('Data Usage Restriction')} >
                          <Information fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                        <DataUsageRestrictionField
                          variant='outlined'
                          name='iep'
                          size='small'
                          fullWidth={true}
                          style={{ height: '38.09px', marginBottom: '3px' }}
                          containerstyle={{ width: '100%', padding: '0 0 1px 0' }}
                        />
                    </Grid>
                    <Grid item={true} xs={12}>
                      <div className={classes.textBase}>
                        <Typography
                          variant="h3"
                          color="textSecondary"
                          gutterBottom={true}
                          style={{ margin: 0 }}
                        >
                          {t('Scope')}
                        </Typography>
                        <Tooltip title={t('Scope')} >
                          <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                        </Tooltip>
                      </div>
                      <div className="clearfix" />
                      <ScopeField
                        setFieldValue={setFieldValue}
                        scopeValue={values.scope}
                        name='scope'
                        fullWidth={true}
                        style={{ height: '38.09px' }}
                        containerstyle={{ width: '100%' }}
                        variant='standard'
                      />
                    </Grid>
                  </Grid>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
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

DataSourceEditionContainer.propTypes = {
  handleDisplayEdit: PropTypes.func,
  refreshQuery: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
  enableReferences: PropTypes.bool,
  dataSource: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(DataSourceEditionContainer);
