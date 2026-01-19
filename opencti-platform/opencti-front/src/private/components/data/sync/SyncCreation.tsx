import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik, FormikErrors } from 'formik';
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
import Grid from '@mui/material/Grid';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { dayStartDate } from '../../../../utils/Time';
import SelectField from '../../../../components/fields/SelectField';
import { insertNode } from '../../../../utils/store';
import FilterIconButton from '../../../../components/FilterIconButton';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { deserializeFilterGroupForFrontend } from '../../../../utils/filters/filtersUtils';
import PasswordTextField from '../../../../components/PasswordTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import IngestionCreationUserHandling from '../../../../private/components/data/IngestionCreationUserHandling';
import { PaginationOptions } from '../../../../components/list_lines';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { SyncCreationCheckMutation$data } from '@components/data/sync/__generated__/SyncCreationCheckMutation.graphql';
import { SyncCreationStreamCollectionQuery$data } from '@components/data/sync/__generated__/SyncCreationStreamCollectionQuery.graphql';
import { RelayError } from '../../../../relay/relayTypes';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { SyncImportQuery$data } from '../__generated__/SyncImportQuery.graphql';

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

const syncCreationValidation = () => {
  const { t_i18n } = useFormatter();
  Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    uri: Yup.string().required(t_i18n('This field is required')),
    token: Yup.string(),
    stream_id: Yup.string().required(t_i18n('This field is required')),
    current_state_date: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    listen_deletion: Yup.bool(),
    no_dependencies: Yup.bool(),
    ssl_verify: Yup.bool(),
    synchronized: Yup.bool(),
  });
};

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

interface SynchronizerAddInput {
  name: string;
  uri: string;
  stream_id: string;
  token: string;
  current_state_date?: Date | null;
  listen_deletion?: boolean;
  ssl_verify?: boolean;
  no_dependencies?: boolean;
  synchronized?: boolean;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}
type StreamOption = {
  value: string;
  label: string;
  id: string;
  name: string;
  description?: string | null;
  filters?: string | null;
};

const CreateSynchronizerControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="Synchronizer"
    {...props}
  />
);

interface SyncCreationProps {
  paginationOptions?: PaginationOptions;
  handleClose?: () => void;
  ingestionSynchronizerData?: SyncImportQuery$data['synchronizerAddInputFromImport'];
  triggerButton?: boolean;
  open?: boolean;
  drawerSettings?: {
    title: string;
    button: string;
  };
}

const SyncCreation: FunctionComponent<SyncCreationProps> = ({
  paginationOptions,
  handleClose,
  ingestionSynchronizerData,
  triggerButton = false,
  open = false,
  drawerSettings,
}) => {
  const { t_i18n } = useFormatter();

  const [verified, setVerified] = useState(false);
  const [streams, setStreams] = useState<StreamOption[]>([]);

  const [commitVerify] = useApiMutation(syncCheckMutation);

  const handleVerify = (values: SynchronizerAddInput, setErrors: FormikHelpers<SynchronizerAddInput>['setErrors']) => {
    const userId
      = typeof values.user_id === 'object'
        ? values.user_id?.value
        : values.user_id;
    const input = { ...values, user_id: userId,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: Number(values.confidence_level) }),
    };
    commitVerify({
      variables: { input },
      onCompleted: (response) => {
        const data = response as SyncCreationCheckMutation$data;
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

  const [commitCreation] = useApiMutation(syncCreationMutation);

  const onSubmit: FormikConfig<SynchronizerAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const userId
      = typeof values.user_id === 'object'
        ? values.user_id?.value
        : values.user_id;
    const input = { ...values, user_id: userId,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: Number(values.confidence_level) }),
    };
    commitCreation({
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
      onCompleted: () => {
        setSubmitting(false);
        setVerified(false);
        setStreams([]);
        resetForm();
      },
    });
  };
  const handleGetStreams = (
    values: SynchronizerAddInput,
    setErrors: FormikHelpers<SynchronizerAddInput>['setErrors'],
    currentErrors: FormikErrors<SynchronizerAddInput>,
  ) => {
    const args = { uri: values.uri, token: values.token, ssl_verify: values.ssl_verify ?? false };
    fetchQuery(syncStreamCollectionQuery, args)
      .toPromise()
      .then((result) => {
        const data = result as SyncCreationStreamCollectionQuery$data;
        const streamsData = data.synchronizerFetch ?? [];
        const resultStreams = [
          ...streamsData.map((s) => ({
            value: s?.id,
            label: s?.name,
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
          setStreams(resultStreams as StreamOption[]);
        }
      })
      .catch((e: RelayError) => {
        const errors = e.res.errors.map((err) => ({
          [err.data?.field ?? 'unknownField']: err.data?.message,
        }));
        const formError = R.mergeAll(errors);
        setErrors({ ...currentErrors, ...formError });
        setStreams([]);
      });
  };

  return (
    <Drawer
      title={t_i18n('Create OpenCTI Stream')}
      open={open}
      onClose={handleClose}
      controlledDial={triggerButton ? CreateSynchronizerControlledDial : undefined}
    >
      {({ onClose }) => (
        <Formik<SynchronizerAddInput>
          initialValues={{
            name: ingestionSynchronizerData?.name || '',
            uri: ingestionSynchronizerData?.uri || '',
            token: '',
            current_state_date: ingestionSynchronizerData?.current_state_date ?? dayStartDate(),
            stream_id: ingestionSynchronizerData?.stream_id || '',
            no_dependencies: ingestionSynchronizerData?.no_dependencies ?? false,
            listen_deletion: ingestionSynchronizerData?.listen_deletion ?? true,
            ssl_verify: ingestionSynchronizerData?.ssl_verify ?? false,
            synchronized: ingestionSynchronizerData?.synchronized ?? false,
            user_id: '',
            automatic_user: true,
          }}
          validationSchema={syncCreationValidation()}
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
                  severity="warning"
                  variant="outlined"
                  style={{ position: 'relative',
                    marginTop: 20, width: '100%',
                    overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
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
                      renderValue={(value: string | undefined) => streams.filter((stream) => stream.value === value).at(0)?.name}
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
                  <div style={{
                    width: '100%',
                    marginTop: 20,
                    textAlign: 'right',
                  }}
                  >
                    {streams.length === 0 && (
                      <Button
                        color="secondary"
                        onClick={() => handleGetStreams(values, setErrors, errors)
                        }
                        disabled={isSubmitting}
                        style={{
                          marginLeft: 10,
                        }}
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
                        style={{
                          marginLeft: 10,
                        }}
                      >
                        {t_i18n('Reset')}
                      </Button>
                    )}
                  </div>
                </Alert>
                <IngestionCreationUserHandling
                  default_confidence_level={50}
                  labelTag="S"
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
                      severity="error"
                      variant="outlined"
                      style={{ position: 'relative',
                        marginTop: 20, width: '100%',
                        overflow: 'hidden' }}
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
                <FormButtonContainer>
                  <Button
                    variant="secondary"
                    onClick={handleReset}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => handleVerify(values, setErrors)}
                    disabled={!values.stream_id || isSubmitting}
                  >
                    {t_i18n('Verify')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={!values.stream_id || !verified || isSubmitting}
                  >
                    {drawerSettings?.button ?? t_i18n('Create')}
                  </Button>
                </FormButtonContainer>
              </Form>
            );
          }}
        </Formik>
      )}
    </Drawer>
  );
};
export default SyncCreation;
