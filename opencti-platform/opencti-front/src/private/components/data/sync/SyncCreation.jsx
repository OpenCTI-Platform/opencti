import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import Grid from '@mui/material/Grid';
import { useFormatter } from '../../../../components/i18n';
import {
  commitMutation,
  fetchQuery,
  handleErrorInForm,
  MESSAGING$,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { dayStartDate } from '../../../../utils/Time';
import SelectField from '../../../../components/SelectField';
import { insertNode } from '../../../../utils/store';
import CreatorField from '../../common/form/CreatorField';
import FilterIconButton from '../../../../components/FilterIconButton';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    width: '100%',
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 0px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

const syncCreationMutation = graphql`
  mutation SyncCreationMutation($input: SynchronizerAddInput!) {
    synchronizerAdd(input: $input) {
      ...SyncLine_node
    }
  }
`;

export const syncCheckMutation = graphql`
  mutation SyncCreationCheckMutation($input: SynchronizerAddInput!) {
    synchronizerTest(input: $input)
  }
`;

const syncCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  uri: Yup.string().required(t('This field is required')),
  token: Yup.string(),
  stream_id: Yup.string().required(t('This field is required')),
  current_state_date: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  listen_deletion: Yup.bool(),
  no_dependencies: Yup.bool(),
  ssl_verify: Yup.bool(),
});

export const syncStreamCollectionQuery = graphql`
  query SyncCreationStreamCollectionQuery(
    $uri: String!
    $token: String
    $ssl_verify: Boolean
  ) {
    synchronizerFetch(
      input: { uri: $uri, token: $token, ssl_verify: $ssl_verify }
    ) {
      id
      name
      description
      filters
    }
  }
`;

const SyncCreation = ({ paginationOptions }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [verified, setVerified] = useState(false);
  const [streams, setStreams] = useState([]);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleVerify = (values, setErrors) => {
    const input = { ...values, user_id: values.user_id?.value };
    commitMutation({
      mutation: syncCheckMutation,
      variables: { input },
      onCompleted: (data) => {
        if (data && data.synchronizerTest === 'Connection success') {
          MESSAGING$.notifySuccess(t('Connection successfully verified'));
          setVerified(true);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setVerified(false);
      },
    });
  };
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const input = { ...values, user_id: values.user_id?.value };
    commitMutation({
      mutation: syncCreationMutation,
      variables: { input },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_synchronizers',
          paginationOptions,
          'synchronizerAdd',
        );
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        setVerified(false);
        setStreams([]);
        resetForm();
        handleClose();
      },
    });
  };
  const onReset = () => handleClose();
  const handleGetStreams = (
    { uri, token, ssl_verify },
    setErrors,
    currentErrors,
  ) => {
    const args = { uri, token, ssl_verify: ssl_verify ?? false };
    fetchQuery(syncStreamCollectionQuery, args)
      .toPromise()
      .then((result) => {
        const resultStreams = [
          ...result.synchronizerFetch.map((s) => ({
            value: s.id,
            label: s.name,
            ...s,
          })),
        ];
        if (resultStreams.length === 0) {
          setErrors({
            ...currentErrors,
            uri: 'No remote live stream available',
          });
        } else {
          setErrors(R.dissoc('uri', currentErrors));
          setStreams(resultStreams);
        }
      })
      .catch((e) => {
        const errors = e.res.errors.map((err) => ({
          [err.data.field]: err.data.message,
        }));
        const formError = R.mergeAll(errors);
        setErrors({ ...currentErrors, ...formError });
        setStreams([]);
      });
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a synchronizer')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              uri: '',
              token: '',
              current_state_date: dayStartDate(),
              stream_id: '',
              no_dependencies: false,
              listen_deletion: true,
              ssl_verify: false,
            }}
            validationSchema={syncCreationValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              values,
              setFieldValue,
              setErrors,
              errors,
            }) => {
              return (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Alert
                    icon={false}
                    classes={{ root: classes.alert, message: classes.message }}
                    severity="warning"
                    variant="outlined"
                    style={{ position: 'relative' }}
                  >
                    <AlertTitle>{t('Remote OpenCTI configuration')}</AlertTitle>
                    <Tooltip
                      title={t(
                        'You need to configure a valid remote OpenCTI. Token is optional to consume public streams',
                      )}
                    >
                      <InformationOutline
                        fontSize="small"
                        color="primary"
                        style={{ position: 'absolute', top: 10, right: 18 }}
                      />
                    </Tooltip>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="uri"
                      label={t('Remote OpenCTI URL')}
                      fullWidth={true}
                      disabled={streams.length > 0}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="token"
                      label={t('Remote OpenCTI token')}
                      fullWidth={true}
                      disabled={streams.length > 0}
                      style={fieldSpacingContainerStyle}
                    />
                    {streams.length > 0 && (
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="stream_id"
                        label={t('Remote OpenCTI stream ID')}
                        inputProps={{ name: 'stream_id', id: 'stream_id' }}
                        containerstyle={fieldSpacingContainerStyle}
                        renderValue={(value) => streams
                          .filter((stream) => stream.value === value)
                          .at(0).name
                        }
                      >
                        {streams.map(
                          ({ value, label, name, description, filters }) => (
                            <EnrichedTooltip
                              key={value}
                              value={value}
                              style={{ overflow: 'hidden' }}
                              title={
                                <Grid
                                  container
                                  spacing={1}
                                  style={{ overflow: 'hidden' }}
                                >
                                  <Grid key={name} item xs={12}>
                                    <Typography>{name}</Typography>
                                  </Grid>
                                  <Grid key={description} item xs={12}>
                                    <Typography>{description}</Typography>
                                  </Grid>
                                  <Grid key={filters} item xs={12}>
                                    <FilterIconButton
                                      filters={JSON.parse(filters)}
                                      classNameNumber={3}
                                      styleNumber={3}
                                    />
                                  </Grid>
                                </Grid>
                              }
                              placement="bottom-start"
                            >
                              <MenuItem key={value} value={value}>
                                {label}
                              </MenuItem>
                            </EnrichedTooltip>
                          ),
                        )}
                      </Field>
                    )}
                    <div className={classes.buttons}>
                      {streams.length === 0 && (
                        <Button
                          variant="contained"
                          color="secondary"
                          onClick={() => handleGetStreams(values, setErrors, errors)
                          }
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Validate')}
                        </Button>
                      )}
                      {streams.length > 0 && (
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={() => {
                            setFieldValue('stream_id', '');
                            setVerified(false);
                            setStreams([]);
                          }}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Reset')}
                        </Button>
                      )}
                    </div>
                  </Alert>
                  <CreatorField
                    name='user_id'
                    label={t(
                      'User responsible for data creation (empty = System)',
                    )}
                    containerStyle={fieldSpacingContainerStyle}
                  />
                  <Field
                    component={DateTimePickerField}
                    name="current_state_date"
                    TextFieldProps={{
                      label: t('Starting synchronization (empty = from start)'),
                      variant: 'standard',
                      fullWidth: true,
                      style: { marginTop: 20 },
                    }}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="listen_deletion"
                    containerstyle={{ marginTop: 20 }}
                    label={t('Take deletions into account')}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="no_dependencies"
                    label={t('Avoid dependencies resolution')}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="ssl_verify"
                    label={t('Verify SSL certificate')}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={() => handleVerify(values, setErrors)}
                      disabled={!values.stream_id || isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Verify')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={!values.stream_id || !verified || isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              );
            }}
          </Formik>
        </div>
      </Drawer>
    </div>
  );
};
export default SyncCreation;
