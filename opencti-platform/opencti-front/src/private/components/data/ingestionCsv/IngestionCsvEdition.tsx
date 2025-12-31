import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useMemo, useState } from 'react';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { Field, Form, Formik, FormikErrors } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CreatorField from '@components/common/form/CreatorField';
import CommitMessage from '@components/common/form/CommitMessage';
import {
  IngestionCsvEditionFragment_ingestionCsv$data,
  IngestionCsvEditionFragment_ingestionCsv$key,
} from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import CsvMapperField, { CsvMapperFieldOption, csvMapperQuery } from '@components/common/form/CsvMapperField';
import Button from '@common/button/Button';
import IngestionCsvFeedTestDialog from '@components/data/ingestionCsv/IngestionCsvFeedTestDialog';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import IngestionSchedulingField from '@components/data/IngestionSchedulingField';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import IngestionCsvInlineMapperForm from '@components/data/ingestionCsv/IngestionCsvInlineMapperForm';
import { CsvMapperAddInput } from '@components/data/csvMapper/CsvMapperUtils';
import IngestionCsvEditionUserHandling from '@components/data/ingestionCsv/IngestionCsvEditionUserHandling';
import { useTheme } from '@mui/styles';
import { convertMapper, convertUser } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { adaptFieldValue } from '../../../../utils/String';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import { USER_CHOICE_MARKING_CONFIG } from '../../../../utils/csvMapperUtils';
import {
  BASIC_AUTH,
  BEARER_AUTH,
  CERT_AUTH,
  extractCA,
  extractCert,
  extractKey,
  extractPassword,
  extractToken,
  extractUsername,
  updateAuthenticationFields,
} from '../../../../utils/ingestionAuthentificationUtils';
import PasswordTextField from '../../../../components/PasswordTextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { RootMe_data$data } from '../../../__generated__/RootMe_data.graphql';
import IngestionCsvInlineWrapper from './IngestionCsvInlineWrapper';

export const initIngestionValue = (ingestionCsvData: IngestionCsvEditionFragment_ingestionCsv$data, me: RootMe_data$data) => {
  return {
    ...{
      name: ingestionCsvData.name,
      description: ingestionCsvData.description,
      scheduling_period: ingestionCsvData.scheduling_period ?? 'auto',
      uri: ingestionCsvData.uri,
      authentication_type: ingestionCsvData.authentication_type,
      authentication_value: ingestionCsvData.authentication_value,
      ingestion_running: ingestionCsvData.ingestion_running,
      // In case the csv_mapper_id is not know, that mean we are in the older model where we link to an id by default
      csv_mapper_type: ingestionCsvData.csv_mapper_type === null ? true : ingestionCsvData.csv_mapper_type === 'id',
      csv_mapper: ingestionCsvData.csv_mapper_type === 'inline' ? ingestionCsvData.csvMapper as CsvMapperAddInput : undefined,
      csv_mapper_id: ingestionCsvData.csv_mapper_type === 'inline' ? null : convertMapper(ingestionCsvData, 'csvMapper'),
      user_id: convertUser(ingestionCsvData, 'user'),
      references: undefined,
      markings: me.allowed_marking?.filter(
        (marking) => ingestionCsvData.markings?.includes(marking.id),
      ).map((marking) => ({
        label: marking.definition ?? '',
        value: marking.id,
      })) ?? [],
    },
    ...(ingestionCsvData.authentication_type === BEARER_AUTH
      ? {
          token: extractToken(ingestionCsvData.authentication_value),
        }
      : {
          token: '',
        }),
    ...(ingestionCsvData.authentication_type === BASIC_AUTH
      ? {
          username: extractUsername(ingestionCsvData.authentication_value),
          password: extractPassword(ingestionCsvData.authentication_value),
        }
      : {
          username: '',
          password: '',
        }),
    ...(ingestionCsvData.authentication_type === CERT_AUTH
      ? {
          cert: extractCert(ingestionCsvData.authentication_value),
          key: extractKey(ingestionCsvData.authentication_value),
          ca: extractCA(ingestionCsvData.authentication_value),
        }
      : {
          cert: '',
          key: '',
          ca: '',
        }),
  };
};

export const ingestionCsvEditionPatch = graphql`
  mutation IngestionCsvEditionPatchMutation($id: ID!, $input: [EditInput!]!) {
    ingestionCsvFieldPatch(id: $id, input: $input) {
      ...IngestionCsvEditionFragment_ingestionCsv
    }
  }
`;

export const ingestionCsvEditionFragment = graphql`
  fragment IngestionCsvEditionFragment_ingestionCsv on IngestionCsv {
    id
    name
    description
    scheduling_period
    uri
    authentication_type
    authentication_value
    ingestion_running
    csv_mapper_type
    csvMapper {
      id
      name
      has_header
      separator
      skipLineChar
      representations {
        id
        type
        target {
          entity_type
          column_based {
            column_reference
            operator
            value
          }
        }
        attributes {
          key
          column {
            column_name
            configuration {
              separator
              pattern_date
            }
          }
          default_values {
            id
            name
          }
          based_on {
            representations
          }
        }
      }
    }
    user {
      id
      entity_type
      name
    }
    markings
    duplicateCsvMapper {
      id
      name
      has_header
      separator
      skipLineChar
      representations {
        id
        type
        target {
          entity_type
          column_based {
            column_reference
            operator
            value
          }
        }
        attributes {
          key
          column {
            column_name
            configuration {
              separator
              pattern_date
            }
          }
          default_values {
            id
            name
          }
          based_on {
            representations
          }
        }
      }
    }
  }
`;

interface IngestionCsvEditionProps {
  ingestionCsv: IngestionCsvEditionFragment_ingestionCsv$key;
  handleClose: () => void;
  enableReferences?: boolean;
}

export interface IngestionCsvEditionForm {
  message?: string | null;
  references?: ExternalReferencesValues;
  name: string;
  description?: string | null;
  scheduling_period?: string | null;
  uri: string;
  authentication_type: string;
  authentication_value?: string | null;
  token?: string;
  username?: string;
  password?: string;
  cert?: string;
  key?: string;
  ca?: string;
  ingestion_running?: boolean | null;
  csv_mapper_id: string | FieldOption | null;
  user_id: string | FieldOption;
  markings: FieldOption[];
  csv_mapper?: CsvMapperAddInput;
  csv_mapper_type: boolean;
}

type FieldValue
  = FieldOption
    | FieldOption[]
    | CsvMapperFieldOption
    | string
    | string[]
    | number
    | number[]
    | null
    | CsvMapperAddInput;

const resolveHasUserChoiceCsvMapper = (option: CsvMapperFieldOption) => {
  return option?.representations?.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some(
        (value) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value?.name === USER_CHOICE_MARKING_CONFIG),
      ),
    ),
  );
};

const IngestionCsvEdition: FunctionComponent<IngestionCsvEditionProps> = ({
  ingestionCsv,
  handleClose,
  enableReferences = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  const ingestionCsvData = useFragment(ingestionCsvEditionFragment, ingestionCsv);
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(ingestionCsvData.csvMapper.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && (attribute.default_values && attribute.default_values?.some(
        (value: string | { name: string }) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value.name === USER_CHOICE_MARKING_CONFIG),
      )),
    ),
  ));
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const [creatorId, setCreatorId] = useState(ingestionCsvData.user?.id);
  const isGranted = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const onCreatorSelection = async (option: FieldOption) => {
    setCreatorId(option.value);
  };
  const { me } = useAuth();
  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    scheduling_period: Yup.string().required(t_i18n('This field is required')),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    user_id: Yup.mixed().nullable(),
    token: Yup.string().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    csv_mapper: Yup.object().nullable(),
    csv_mapper_id: Yup.mixed().required(t_i18n('This field is required')),
    csv_mapper_type: Yup.string(),
    markings: Yup.array().required(),
  };

  const ingestionCsvValidator = useSchemaEditionValidation('IngestionCsv', basicShape);
  const [commitUpdate] = useApiMutation(ingestionCsvEditionPatch);

  const onSubmit: FormikConfig<IngestionCsvEditionForm>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    commitUpdate({
      variables: {
        id: ingestionCsvData.id,
        input: inputValues,
        commitMessage: commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: FieldValue,
    formValues?: IngestionCsvEditionForm,
  ) => {
    let finalValue = value as string | undefined;
    let finalName = name;
    const additionalValue: Record<'key' | 'value', string>[] = [];
    const isExistingCsvMappers = value === 'true';

    // Handle authentication fields -- If you change something here, please have a look at IngestionTaxiiEdition
    const { username, password, token, cert, key, ca } = formValues || {};

    if (name === 'token') {
      finalName = 'authentication_value';
      finalValue = token;
    }

    // re-compose username:password
    if (name === 'username') {
      finalName = 'authentication_value';
      finalValue = `${value}:${password}`;
    }
    if (name === 'password') {
      finalName = 'authentication_value';
      finalValue = `${username}:${value}`;
    }

    // re-compose cert:key:ca
    if (name === 'cert') {
      finalName = 'authentication_value';
      finalValue = `${value}:${key}:${ca}`;
    }
    if (name === 'key') {
      finalName = 'authentication_value';
      finalValue = `${cert}:${value}:${ca}`;
    }
    if (name === 'ca') {
      finalName = 'authentication_value';
      finalValue = `${cert}:${key}:${value}`;
    }

    if (name === 'csv_mapper_type') {
      const usingExistingMapper = isExistingCsvMappers;

      finalValue = usingExistingMapper ? 'id' : 'inline';

      // Don't proceed if using an existing CSV mapper but no mapper ID is defined
      const missingMapperId = usingExistingMapper && !formValues?.csv_mapper_id;
      // Don't proceed if creating an inline CSV mapper but no mapper data is provided
      const missingInlineMapper = !usingExistingMapper && !formValues?.csv_mapper;

      // Avoid sending request if required mapper data is missing
      if (missingMapperId || missingInlineMapper) {
        return;
      }
    }
    if (name === 'csv_mapper') {
      finalValue = JSON.stringify(value);
      additionalValue.push({ value: 'inline', key: 'csv_mapper_type' });
    }
    if (name === 'csv_mapper_id' || name === 'user_id') {
      finalValue = (value as FieldOption).value;
    }
    if (name === 'csv_mapper_id') {
      const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceCsvMapper(value as CsvMapperFieldOption);
      setHasUserChoiceCsvMapper(hasUserChoiceCsvMapperRepresentations);
      additionalValue.push({ key: 'csv_mapper_type', value: 'id' });
    }
    if (name === 'user_id') {
      onCreatorSelection(value as FieldOption).then();
    }
    ingestionCsvValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: ingestionCsvData.id,
            input: [{ key: finalName, value: finalValue || '' }, ...additionalValue],
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = useMemo(() => initIngestionValue(ingestionCsvData, me), [ingestionCsvData.id]);
  const [tempStateInlineCsv, setTempStateInlineCsv] = useState(initialValues.csv_mapper);
  const queryRef = useQueryLoading<CsvMapperFieldSearchQuery>(csvMapperQuery);
  const defaultMarkingOptions = (me.default_marking?.flatMap(({ values }) => (values ?? [{ id: '', definition: '' }])?.map(({ id, definition }) => ({ label: definition, value: id }))) ?? []) as FieldOption[];

  const updateCsvMapper = async (
    setFieldValue: (field: string, option: FieldOption, shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvEditionForm>>,
    option: CsvMapperFieldOption,
  ) => {
    await setFieldValue('csv_mapper_id', option);
  };

  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvEditionForm>>,
    values: IngestionCsvEditionForm,
    newHasUserChoiceCsvMapper: boolean,
  ) => {
    const markings = newHasUserChoiceCsvMapper ? values.markings : defaultMarkingOptions;
    await setFieldValue('markings', markings);
    handleSubmitField('markings', markings.map(({ value }: FieldOption) => value));
  };

  return (
    <Formik<IngestionCsvEditionForm>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={ingestionCsvValidator}
      onSubmit={onSubmit}
    >
      {({
        values,
        submitForm,
        isSubmitting,
        setFieldValue,
        isValid,
        dirty,
      }) => (
        <>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 2 }}>
            <Tabs
              value={currentTab}
              onChange={(_event, value) => handleChangeTab(value)}
            >
              <Tab label={t_i18n('Overview')} />
              <Tab label={t_i18n('Inline csv mapper')} disabled={values.csv_mapper_type} />
            </Tabs>
          </Box>
          <Box sx={{ display: currentTab === 1 ? 'block' : 'none' }}>
            <IngestionCsvInlineWrapper>
              <IngestionCsvInlineMapperForm
                csvMapper={values.csv_mapper as CsvMapperAddInput}
                setCSVMapperFieldValue={(name, value) => {
                  handleSubmitField(name, value);
                  setTempStateInlineCsv(value);
                }}
                returnCSVFormat={(_, value) => setTempStateInlineCsv(value)}
              />
            </IngestionCsvInlineWrapper>
          </Box>

          <Form>
            <Box sx={{ display: currentTab === 0 ? 'block' : 'none' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
                onSubmit={handleSubmitField}
              />
              <IngestionSchedulingField handleSubmitField={handleSubmitField} />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t_i18n('CSV URL')}
                fullWidth={true}
                onSubmit={handleSubmitField}
                style={fieldSpacingContainerStyle}
              />
              <CreatorField
                name="user_id"
                label={t_i18n('User responsible for data creation')}
                onChange={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                showConfidence
              />
              {ingestionCsvData.user?.name === 'SYSTEM'
                && (
                  <IngestionCsvEditionUserHandling
                    key={values.name}
                    feedName={values.name}
                    onAutoUserCreated={() => setFieldValue('user_id', `[F] ${values.name}`)}
                    ingestionCsvDataId={ingestionCsvData.id}
                  />
                )
              }
              <Box sx={{
                marginTop: 2,
              }}
              >
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="csv_mapper_type"
                  label={t_i18n('Existing csv mappers')}
                  onChange={(name: string, value: string) => handleSubmitField(name, value, values)}
                />
              </Box>
              {
                values.csv_mapper_type && queryRef && (
                  <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
                    <Box sx={{ width: '100%', marginTop: 5 }}>
                      <Alert
                        severity="info"
                        variant="outlined"
                        style={{ padding: '0px 10px 0px 10px' }}
                      >
                        {t_i18n('Depending on the selected CSV mapper configurations, marking definition levels can be set in the dedicated field.')}<br />
                        <br />
                        {t_i18n('If the CSV mapper is configured with "Use default markings definitions of the user", the default markings of the user responsible for data creation are applied to the ingested entities. Otherwise, you can choose markings to apply.')}<br />
                      </Alert>
                    </Box>
                    <CsvMapperField
                      name="csv_mapper_id"
                      isOptionEqualToValue={(option: FieldOption, value: FieldOption) => option.value === value.value}
                      onChange={async (_, option) => {
                        handleSubmitField('csv_mapper_id', option);
                        await updateCsvMapper(setFieldValue, option);
                        const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceCsvMapper(option as CsvMapperFieldOption);
                        await updateObjectMarkingField(setFieldValue, values, hasUserChoiceCsvMapperRepresentations);
                      }}
                      queryRef={queryRef}
                    />
                  </React.Suspense>
                )
              }
              {
                hasUserChoiceCsvMapper && (
                  <ObjectMarkingField
                    name="markings"
                    isOptionEqualToValue={(option: FieldOption, value: FieldOption) => option.value === value.value}
                    label={t_i18n('Marking definition levels')}
                    style={fieldSpacingContainerStyle}
                    allowedMarkingOwnerId={isGranted ? creatorId : undefined}
                    setFieldValue={setFieldValue}
                    onChange={(name, value) => {
                      if (value.length) {
                        handleSubmitField(name, value.map((marking) => marking.value));
                      }
                    }}
                  />
                )
              }
              <Field
                component={SelectField}
                variant="standard"
                name="authentication_type"
                label={t_i18n('Authentication type')}
                onChange={(_: string, value: string) => updateAuthenticationFields(setFieldValue, value)}
                onSubmit={handleSubmitField}
                fullWidth={true}
                containerstyle={{
                  width: '100%',
                  marginTop: 20,
                }}
              >
                <MenuItem value="none">{t_i18n('None')}</MenuItem>
                <MenuItem value="basic">{t_i18n('Basic user / password')}</MenuItem>
                <MenuItem value="bearer">{t_i18n('Bearer token')}</MenuItem>
                <MenuItem value="certificate">
                  {t_i18n('Client certificate')}
                </MenuItem>
              </Field>
              {values.authentication_type === BASIC_AUTH && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="username"
                    label={t_i18n('Username')}
                    onSubmit={(name: string, value: FieldValue) => handleSubmitField(name, value, values)}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="password"
                    label={t_i18n('Password')}
                    isSecret
                    onSubmit={(name: string, submitValue: string) => handleSubmitField(name, submitValue, values)}
                  />
                </>
              )}
              {values.authentication_type === BEARER_AUTH && (
                <PasswordTextField
                  name="token"
                  label={t_i18n('Token')}
                  isSecret
                  onSubmit={(name: string, submitValue: string) => handleSubmitField(name, submitValue, values)}
                />
              )}
              {values.authentication_type === CERT_AUTH && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="cert"
                    label={t_i18n('Certificate (base64)')}
                    onSubmit={(name: string, value: FieldValue) => handleSubmitField(name, value, values)}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="key"
                    label={t_i18n('Key (base64)')}
                    isSecret
                    onSubmit={(name: string, submitValue: string) => handleSubmitField(name, submitValue, values)}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="ca"
                    label={t_i18n('CA certificate (base64)')}
                    onSubmit={(name: string, value: FieldValue) => handleSubmitField(name, value, values)}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                </>
              )}
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={values.references}
                  id={ingestionCsvData.id}
                />
              )}
              <Box sx={{ width: '100%', marginTop: 5 }}>
                <Alert
                  severity="info"
                  variant="outlined"
                  style={{ padding: '0px 10px 0px 10px' }}
                >
                  {t_i18n('Please, verify the validity of the selected CSV mapper for the given URL.')}<br />
                  {t_i18n('Only successful tests allow the ingestion edition.')}
                </Alert>
              </Box>
            </Box>
            <div style={{ marginTop: 20, textAlign: 'right' }}>
              <Button
                color="secondary"
                onClick={() => setOpen(true)}
                style={{ marginLeft: theme.spacing(2) }}
                disabled={!(values.uri && (values.csv_mapper_id || values.csv_mapper))}
              >
                {t_i18n('Verify')}
              </Button>
            </div>
            <IngestionCsvFeedTestDialog
              open={open}
              onClose={() => setOpen(false)}
              values={{
                ...values,
                csv_mapper: tempStateInlineCsv,
                csv_mapper_type: values.csv_mapper_type ? 'id' : 'inline',
              }}
            />
          </Form>
        </>
      )}
    </Formik>
  );
};

export default IngestionCsvEdition;
