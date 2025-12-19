import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { Field, Form, Formik, FormikErrors } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CreatorField from '@components/common/form/CreatorField';
import CommitMessage from '@components/common/form/CommitMessage';
import JsonMapperField, { JsonMapperFieldOption, jsonMapperQuery } from '@components/common/form/JsonMapperField';
import Button from '@common/button/Button';
import IngestionJsonMapperTestDialog from '@components/data/ingestionJson/IngestionJsonMapperTestDialog';
import { IngestionJsonEditionFragment_ingestionJson$key } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionFragment_ingestionJson.graphql';
import { JsonMapperFieldSearchQuery } from '@components/common/form/__generated__/JsonMapperFieldSearchQuery.graphql';
import { QueryAttributeFieldAdd } from '@components/common/form/QueryAttributeField';
import { HeaderFieldAdd } from '@components/common/form/HeaderField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { IngestionJsonAttributes, IngestionJsonHeader } from '@components/data/ingestionJson/IngestionJsonCreation';
import IngestionSchedulingField from '@components/data/IngestionSchedulingField';
import { useTheme } from '@mui/styles';
import { convertMapper, convertUser } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
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

const ingestionJsonEditionPatch = graphql`
  mutation IngestionJsonEditionPatchMutation($id: ID!, $input: IngestionJsonAddInput!) {
    ingestionJsonEdit(id: $id, input: $input) {
      ...IngestionJsonEditionFragment_ingestionJson
    }
  } 
`;

export const ingestionJsonEditionFragment = graphql`
  fragment IngestionJsonEditionFragment_ingestionJson on IngestionJson {
    id
    name
    description
    scheduling_period
    uri
    body
    verb
    headers {
      name
      value
    }
    query_attributes {
      type
      data_operation
      default
      exposed
      from
      to
      state_operation
    }
    pagination_with_sub_page
    pagination_with_sub_page_query_verb
    pagination_with_sub_page_attribute_path
    pagination_with_sub_page
    authentication_type
    authentication_value
    ingestion_running
    jsonMapper {
      id
      name
    }
    user {
      id
      entity_type
      name
    }
    markings
  }
`;

interface IngestionJsonEditionProps {
  ingestionJson: IngestionJsonEditionFragment_ingestionJson$key;
  handleClose: () => void;
  enableReferences?: boolean;
}

export interface IngestionJsonEditionForm {
  message?: string | null;
  references?: ExternalReferencesValues;
  name: string;
  description?: string | null;
  scheduling_period?: string | null;
  uri: string;
  verb: string;
  body: string | null | undefined;
  pagination_with_sub_page: boolean;
  pagination_with_sub_page_query_verb: string | null | undefined;
  pagination_with_sub_page_attribute_path: string | null | undefined;
  headers: IngestionJsonHeader[];
  query_attributes: IngestionJsonAttributes[];
  authentication_type: string;
  authentication_value?: string | null;
  ingestion_running?: boolean | null;
  json_mapper_id: string | FieldOption;
  user_id: string | FieldOption;
  username?: string;
  password?: string;
  token?: string;
  cert?: string;
  key?: string;
  ca?: string;
  markings: FieldOption[];
}

const resolveHasUserChoiceJsonMapper = (option: JsonMapperFieldOption) => {
  return option?.representations?.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some(
        (value) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value?.name === USER_CHOICE_MARKING_CONFIG),
      ),
    ),
  );
};

const IngestionJsonEdition: FunctionComponent<IngestionJsonEditionProps> = ({
  ingestionJson,
  handleClose,
  enableReferences = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  const [isCreateDisabled, setIsCreateDisabled] = useState(true);
  const ingestionJsonData = useFragment(ingestionJsonEditionFragment, ingestionJson);
  // const [hasUserChoiceJsonMapper, setHasUserChoiceJsonMapper] = useState(ingestionJsonData.jsonMapper.representations.some(
  //   (representation) => representation.attributes.some(
  //     (attribute) => attribute.key === 'objectMarking' && (attribute.default_values && attribute.default_values?.some(
  //       (value: string | { name: string }) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value.name === USER_CHOICE_MARKING_CONFIG),
  //     )),
  //   ),
  // ));
  // const [creatorId, setCreatorId] = useState(ingestionJsonData.user?.id);
  // const isGranted = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  // const onCreatorSelection = async (option: Option) => {
  //   setCreatorId(option.value);
  // };
  const { me } = useAuth();
  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    user_id: Yup.mixed().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    token: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    json_mapper_id: Yup.mixed().required(t_i18n('This field is required')),
    markings: Yup.array().required(),
  };

  const ingestionJsonValidator = useSchemaEditionValidation('IngestionJson', basicShape);
  const [commitUpdate] = useApiMutation(ingestionJsonEditionPatch);

  const onSubmit: FormikConfig<IngestionJsonEditionForm>['onSubmit'] = (values, { setSubmitting }) => {
    let authenticationValue;
    if (values.authentication_type === BASIC_AUTH) {
      authenticationValue = `${values.username}:${values.password}`;
    } else if (values.authentication_type === BEARER_AUTH) {
      authenticationValue = values.token;
    } else if (values.authentication_type === CERT_AUTH) {
      authenticationValue = `${values.cert}:${values.key}:${values.ca}`;
    }
    const markings = values.markings?.map((option) => option.value);
    const input = {
      name: values.name,
      description: values.description,
      scheduling_period: values.scheduling_period,
      uri: values.uri,
      verb: values.verb,
      body: values.body,
      headers: values.headers,
      query_attributes: values.query_attributes,
      pagination_with_sub_page: values.pagination_with_sub_page,
      pagination_with_sub_page_query_verb: values.pagination_with_sub_page_query_verb,
      pagination_with_sub_page_attribute_path: values.pagination_with_sub_page_attribute_path,
      json_mapper_id: typeof values.json_mapper_id === 'string' ? values.json_mapper_id : values.json_mapper_id?.value,
      authentication_type: values.authentication_type,
      authentication_value: authenticationValue,
      user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id?.value,
      markings: markings ?? [],
    };

    commitUpdate({
      variables: { id: ingestionJsonData.id, input },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const initialValues = {
    name: ingestionJsonData.name,
    description: ingestionJsonData.description,
    scheduling_period: ingestionJsonData.scheduling_period ?? 'auto',
    uri: ingestionJsonData.uri,
    body: ingestionJsonData.body,
    verb: ingestionJsonData.verb,
    headers: (ingestionJsonData.headers ?? []) as IngestionJsonHeader[],
    pagination_with_sub_page: ingestionJsonData.pagination_with_sub_page ?? false,
    pagination_with_sub_page_query_verb: ingestionJsonData.pagination_with_sub_page_query_verb,
    pagination_with_sub_page_attribute_path: ingestionJsonData.pagination_with_sub_page_attribute_path,
    query_attributes: (ingestionJsonData.query_attributes ?? []) as IngestionJsonAttributes[],
    authentication_type: ingestionJsonData.authentication_type,
    authentication_value: ingestionJsonData.authentication_value,
    ingestion_running: ingestionJsonData.ingestion_running,
    json_mapper_id: convertMapper(ingestionJsonData, 'jsonMapper'),
    user_id: convertUser(ingestionJsonData, 'user'),
    references: undefined,
    markings: me.allowed_marking?.filter(
      (marking) => ingestionJsonData.markings?.includes(marking.id),
    ).map((marking) => ({
      label: marking.definition ?? '',
      value: marking.id,
    })) ?? [],
    ...(ingestionJsonData.authentication_type === BEARER_AUTH
      ? {
          token: extractToken(ingestionJsonData.authentication_value),
        }
      : {
          token: '',
        }),
    ...(ingestionJsonData.authentication_type === BASIC_AUTH
      ? {
          username: extractUsername(ingestionJsonData.authentication_value),
          password: extractPassword(ingestionJsonData.authentication_value),
        }
      : {
          username: '',
          password: '',
        }),
    ...(ingestionJsonData.authentication_type === CERT_AUTH
      ? {
          cert: extractCert(ingestionJsonData.authentication_value),
          key: extractKey(ingestionJsonData.authentication_value),
          ca: extractCA(ingestionJsonData.authentication_value),
        }
      : {
          cert: '',
          key: '',
          ca: '',
        }),
  };

  const queryRef = useQueryLoading<JsonMapperFieldSearchQuery>(jsonMapperQuery);

  const defaultMarkingOptions = (me.default_marking?.flatMap(({ values }) => (values ?? [{ id: '', definition: '' }])?.map(({ id, definition }) => ({ label: definition, value: id }))) ?? []) as FieldOption[];
  const updateJsonMapper = async (
    setFieldValue: (field: string, option: FieldOption, shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonEditionForm>>,
    option: JsonMapperFieldOption,
  ) => {
    await setFieldValue('json_mapper_id', option);
  };
  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonEditionForm>>,
    values: IngestionJsonEditionForm,
    newHasUserChoiceJsonMapper: boolean,
  ) => {
    const markings = newHasUserChoiceJsonMapper ? values.markings : defaultMarkingOptions;
    await setFieldValue('markings', markings);
  };

  return (
    <Formik<IngestionJsonEditionForm>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={ingestionJsonValidator}
      onReset={handleClose}
      onSubmit={onSubmit}
    >
      {({
        values,
        submitForm,
        handleReset,
        isSubmitting,
        setFieldValue,
        isValid,
        dirty,
      }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <IngestionSchedulingField />
          <Field
            component={TextField}
            variant="standard"
            name="uri"
            label={t_i18n('HTTP JSON URL')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="verb"
            label={t_i18n('HTTP VERB')}
            fullWidth={true}
            containerstyle={{ width: '100%', marginTop: 20 }}
          >
            <MenuItem value="GET">GET</MenuItem>
            <MenuItem value="POST">POST</MenuItem>
          </Field>

          {values.verb === 'POST' && (
            <>
              <Field
                component={TextField}
                name="body"
                label={t_i18n('HTTP BODY POST')}
                required={values.verb === 'POST'}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={fieldSpacingContainerStyle}
                askAi={false}
              />
            </>
          )}

          <QueryAttributeFieldAdd
            id="query_attributes"
            name="query_attributes"
            values={values.query_attributes ?? []}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />

          <HeaderFieldAdd
            id="headers"
            name="headers"
            values={values.headers ?? []}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />

          <Alert severity="info" variant="standard" style={{ position: 'relative', marginTop: 20, marginBottom: 20, padding: '0px 10px 10px 10px' }}>
            <div>
              {t_i18n('For specific api (like Trino), sometimes it required to have sub pagination. To activate only for this specific use cases')}
            </div>
            <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
              <FormControlLabel
                control={<Switch defaultChecked={!!values.pagination_with_sub_page} />}
                style={{ marginLeft: 1 }}
                name="pagination_with_sub_page"
                onChange={(_, checked) => setFieldValue('pagination_with_sub_page', checked)}
                label={t_i18n('Sub pagination')}
              />
            </Box>
            {!!values.pagination_with_sub_page && (
              <>
                <Field
                  component={SelectField}
                  variant="standard"
                  name="pagination_with_sub_page_query_verb"
                  label={t_i18n('Sub pagination verb')}
                  fullWidth={true}
                  containerstyle={{
                    width: '100%',
                    marginTop: 20,
                  }}
                >
                  <MenuItem value="GET">GET</MenuItem>
                  <MenuItem value="POST">POST</MenuItem>
                </Field>

                <Field
                  component={TextField}
                  variant="standard"
                  name="pagination_with_sub_page_attribute_path"
                  label={t_i18n('Attribute path to get next uri')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
              </>
            )}
          </Alert>

          <CreatorField
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            containerStyle={fieldSpacingContainerStyle}
            showConfidence
          />
          {
            queryRef && (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
                <Box sx={{ width: '100%', marginTop: 5 }}>
                  <Alert
                    severity="info"
                    variant="outlined"
                    style={{ padding: '0px 10px 0px 10px' }}
                  >
                    {t_i18n('Depending on the selected JSON mapper configurations, marking definition levels can be set in the dedicated field.')}<br />
                    <br />
                    {t_i18n('If the JSON mapper is configured with "Use default markings definitions of the user", the default markings of the user responsible for data creation are applied to the ingested entities. Otherwise, you can choose markings to apply.')}<br />
                  </Alert>
                </Box>
                <JsonMapperField
                  name="json_mapper_id"
                  isOptionEqualToValue={(option: FieldOption, value: FieldOption) => option.value === value.value}
                  onChange={async (_, option) => {
                    await updateJsonMapper(setFieldValue, option);
                    const hasUserChoiceJsonMapperRepresentations = resolveHasUserChoiceJsonMapper(option as JsonMapperFieldOption);
                    await updateObjectMarkingField(setFieldValue, values, hasUserChoiceJsonMapperRepresentations);
                  }}
                  queryRef={queryRef}
                />
              </React.Suspense>
            )
          }
          <Field
            component={SelectField}
            variant="standard"
            name="authentication_type"
            label={t_i18n('Authentication type')}
            fullWidth={true}
            containerstyle={{
              width: '100%',
              marginTop: 20,
            }}
            onChange={(_: string, value: string) => updateAuthenticationFields(setFieldValue, value)}
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
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="password"
                label={t_i18n('Password')}
                isSecret
              />
            </>
          )}
          {values.authentication_type === BEARER_AUTH && (
            <PasswordTextField
              name="token"
              label={t_i18n('Token')}
              isSecret
            />
          )}
          {values.authentication_type === CERT_AUTH && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="cert"
                label={t_i18n('Certificate (base64)')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="key"
                label={t_i18n('Key (base64)')}
                isSecret
              />
              <Field
                component={TextField}
                variant="standard"
                name="ca"
                label={t_i18n('CA certificate (base64)')}
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
              id={ingestionJsonData.id}
            />
          )}
          <Box sx={{ width: '100%', marginTop: 5 }}>
            <Alert
              severity="info"
              variant="outlined"
              style={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('Please, verify the validity of the selected JSON mapper for the given URL.')}<br />
              {t_i18n('Only successful tests allow the ingestion edition.')}
            </Alert>
          </Box>
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={() => setOpen(true)}
              style={{ marginLeft: theme.spacing(2) }}
              disabled={!(values.uri && values.json_mapper_id)}
            >
              {t_i18n('Verify')}
            </Button>
            <Button
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting || isCreateDisabled}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n('Save')}
            </Button>
          </div>
          <IngestionJsonMapperTestDialog
            open={open}
            onClose={() => setOpen(false)}
            values={values}
            setIsCreateDisabled={setIsCreateDisabled}
          />
        </Form>
      )}
    </Formik>
  );
};

export default IngestionJsonEdition;
