import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import AccordionDetails from '@mui/material/AccordionDetails';
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
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, fetchQuery, handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { dayStartDate } from '../../../../utils/Time';
import SelectField from '../../../../components/fields/SelectField';
import { insertNode } from '../../../../utils/store';
import CreatorField from '../../common/form/CreatorField';
import FilterIconButton from '../../../../components/FilterIconButton';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { deserializeFilterGroupForFrontend } from '../../../../utils/filters/filtersUtils';
import PasswordTextField from '../../../../components/PasswordTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    width: '100%',
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  synchronized: Yup.bool(),
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

const CreateSynchronizerControlledDial = (props) => (
  <CreateEntityControlledDial
    entityType="Synchronizer"
    {...props}
  />
);

const SyncCreation = ({ paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [verified, setVerified] = useState(false);
  const [streams, setStreams] = useState([]);

  const handleVerify = (values, setErrors) => {
    const input = { ...values, user_id: values.user_id?.value };
    commitMutation({
      mutation: syncCheckMutation,
      variables: { input },
      onCompleted: (data) => {
        if (data && data.synchronizerTest === 'Connection success') {
          MESSAGING$.notifySuccess(t_i18n('Connection successfully verified'));
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
      },
    });
  };
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
    <Drawer
      title={t_i18n('Create a synchronizer')}
      controlledDial={CreateSynchronizerControlledDial}
    >
      {({ onClose }) => (
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
            synchronized: false,
          }}
          validationSchema={syncCreationValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={onClose}
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
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Alert
                  icon={false}
                  classes={{ root: classes.alert, message: classes.message }}
                  severity="warning"
                  variant="outlined"
                  style={{ position: 'relative' }}
                >
                  <AlertTitle>{t_i18n('Remote OpenCTI configuration')}</AlertTitle>
                  <Tooltip
                    title={t_i18n(
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
                    label={t_i18n('Remote OpenCTI URL')}
                    fullWidth={true}
                    disabled={streams.length > 0}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="token"
                    label={t_i18n('Remote OpenCTI token')}
                    disabled={streams.length > 0}
                  />
                  {streams.length > 0 && (
                    <Field
                      component={SelectField}
                      variant="standard"
                      name="stream_id"
                      label={t_i18n('Remote OpenCTI stream ID')}
                      inputProps={{ name: 'stream_id', id: 'stream_id' }}
                      containerstyle={fieldSpacingContainerStyle}
                      renderValue={(value) => streams.filter((stream) => stream.value === value).at(0)
                        .name
                      }
                    >
                      {streams.map(
                        ({ value, label, name, description, filters }) => {
                          const streamsFilters = deserializeFilterGroupForFrontend(filters);
                          return (
                            <EnrichedTooltip
                              key={value}
                              value={value}
                              style={{ overflow: 'hidden' }}
                              title={(
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
                                      filters={streamsFilters}
                                      styleNumber={3}
                                    />
                                  </Grid>
                                </Grid>
                              )}
                              placement="bottom-start"
                            >
                              <MenuItem key={value} value={value}>
                                {label}
                              </MenuItem>
                            </EnrichedTooltip>
                          );
                        },
                      )}
                    </Field>
                  )}
                  <div className={classes.buttons}>
                    {streams.length === 0 && (
                      <Button
                        color="secondary"
                        onClick={() => handleGetStreams(values, setErrors, errors)
                        }
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Validate')}
                      </Button>
                    )}
                    {streams.length > 0 && (
                      <Button
                        onClick={() => {
                          setFieldValue('stream_id', '');
                          setVerified(false);
                          setStreams([]);
                        }}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Reset')}
                      </Button>
                    )}
                  </div>
                </Alert>
                <CreatorField
                  name="user_id"
                  label={t_i18n('User responsible for data creation (empty = System)')}
                  containerStyle={fieldSpacingContainerStyle}
                  showConfidence
                />
                <Field
                  component={DateTimePickerField}
                  name="current_state_date"
                  textFieldProps={{
                    label: t_i18n('Starting synchronization (empty = from start)'),
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
                  label={t_i18n('Take deletions into account')}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="ssl_verify"
                  containerstyle={{ marginBottom: 20 }}
                  label={t_i18n('Verify SSL certificate')}
                />
                <Accordion>
                  <AccordionSummary id="accordion-panel">
                    <Typography>{t_i18n('Advanced options')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert
                      icon={false}
                      classes={{
                        root: classes.alert,
                        message: classes.message,
                      }}
                      severity="error"
                      variant="outlined"
                      style={{ position: 'relative' }}
                    >
                      <div>
                        {t_i18n('Use these options if you know what you are doing')}
                      </div>
                    </Alert>
                    <Field
                      component={SwitchField}
                      containerstyle={{ marginTop: 20 }}
                      type="checkbox"
                      name="no_dependencies"
                      label={t_i18n('Avoid dependencies resolution')}
                    />
                    <div>
                      {t_i18n(
                        'Use this option if you want to prevent any built in relations resolutions (references like createdBy will still be auto resolved)',
                      )}
                    </div>
                    <hr style={{ marginTop: 20, marginBottom: 20 }} />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      containerstyle={{ marginLeft: 2 }}
                      name="synchronized"
                      label={t_i18n('Use perfect synchronization')}
                    />
                    <div>
                      {t_i18n(
                        'Use this option only in case of platform to platform replication',
                      )}
                    </div>
                    <div>
                      {t_i18n(
                        'Every data fetched from this synchronizer will be written as the only source of truth',
                      )}
                    </div>
                  </AccordionDetails>
                </Accordion>
                <div className={classes.buttons}>
                  <Button
                    variant="secondary"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => handleVerify(values, setErrors)}
                    disabled={!values.stream_id || isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Verify')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={!values.stream_id || !verified || isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Create')}
                  </Button>
                </div>
              </Form>
            );
          }}
        </Formik>
      )}
    </Drawer>
  );
};
export default SyncCreation;
