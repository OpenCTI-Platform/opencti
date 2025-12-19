import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik, FormikErrors } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { FormikConfig } from 'formik/dist/types';
import JsonMapperField, { jsonMapperQuery } from '@components/common/form/JsonMapperField';
import IngestionJsonMapperTestDialog from '@components/data/ingestionJson/IngestionJsonMapperTestDialog';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { ingestionJsonEditionContainerQuery } from '@components/data/ingestionJson/IngestionJsonEditionContainer';
import { ingestionJsonEditionFragment } from '@components/data/ingestionJson/IngestionJsonEdition';
import { IngestionJsonLinesPaginationQuery$variables } from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { IngestionJsonEditionFragment_ingestionJson$key } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionFragment_ingestionJson.graphql';
import { IngestionJsonEditionContainerQuery } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionContainerQuery.graphql';
import { IngestionAuthType } from '@components/data/ingestionJson/__generated__/IngestionJsonCreationMutation.graphql';
import { JsonMapperFieldSearchQuery } from '@components/common/form/__generated__/JsonMapperFieldSearchQuery.graphql';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { HeaderFieldAdd } from '@components/common/form/HeaderField';
import { QueryAttributeFieldAdd } from '@components/common/form/QueryAttributeField';
import IngestionSchedulingField from '@components/data/IngestionSchedulingField';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import SelectField from '../../../../components/fields/SelectField';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import { USER_CHOICE_MARKING_CONFIG } from '../../../../utils/csvMapperUtils';
import { convertMapper, convertUser } from '../../../../utils/edition';
import { BASIC_AUTH, CERT_AUTH, extractCA, extractCert, extractKey, extractPassword, extractUsername } from '../../../../utils/ingestionAuthentificationUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import PasswordTextField from '../../../../components/PasswordTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const ingestionJsonCreationMutation = graphql`
  mutation IngestionJsonCreationMutation($input: IngestionJsonAddInput!) {
    ingestionJsonAdd(input: $input) {
      ...IngestionJsonLine_node
    }
  }
`;

interface IngestionJsonCreationContainerProps {
  queryRef?: PreloadedQuery<IngestionJsonEditionContainerQuery>;
  handleClose: () => void;
  open: boolean;
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables | null | undefined;
  isDuplicated: boolean;
}

export interface IngestionJsonHeader {
  name: string;
  value: string;
}

export interface IngestionJsonAttributes {
  type: string;
  from: string;
  to: string;
  data_operation: string;
  state_operation: string;
  default: string;
  exposed: string;
}

export interface IngestionJsonAddInput {
  name: string;
  uri: string;
  verb: string;
  body: string | null | undefined;
  pagination_with_sub_page: boolean;
  pagination_with_sub_page_query_verb: string | null | undefined;
  pagination_with_sub_page_attribute_path: string | null | undefined;
  headers: IngestionJsonHeader[];
  query_attributes: IngestionJsonAttributes[];
  description?: string | null;
  scheduling_period?: string | null;
  json_mapper_id: string | FieldOption;
  authentication_type: IngestionAuthType | string;
  authentication_value?: string | null;
  ingestion_running?: boolean | null;
  user_id: string | FieldOption;
  username?: string;
  password?: string;
  cert?: string;
  key?: string;
  ca?: string;
  markings: FieldOption[];
}

interface IngestionJsonCreationProps {
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables | null | undefined;
  isDuplicated: boolean;
  handleClose: () => void;
  ingestionJson?: IngestionJsonEditionFragment_ingestionJson$key | null;
}

const resolveHasUserChoiceJsonMapper = (option: FieldOption & {
  representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[];
}) => {
  return option.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some(
        (value) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value?.name === USER_CHOICE_MARKING_CONFIG),
      ),
    ),
  );
};

const IngestionJsonCreation: FunctionComponent<IngestionJsonCreationProps> = ({ paginationOptions, isDuplicated, handleClose, ingestionJson }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const ingestionJsonData = useFragment(ingestionJsonEditionFragment, ingestionJson);
  const [isCreateDisabled, setIsCreateDisabled] = useState(true);
  const [hasUserChoiceJsonMapper, setHasUserChoiceJsonMapper] = useState(false);
  const [creatorId, setCreatorId] = useState('');
  const isGranted = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const { me } = useAuth();

  const onCreatorSelection = async (option: FieldOption) => {
    setCreatorId(option.value);
  };
  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonAddInput>>,
    values: IngestionJsonAddInput,
  ) => {
    await setFieldValue('markings', values.markings);
  };
  const onJsonMapperSelection = async (
    option: FieldOption & {
      representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[];
    },
    {
      setFieldValue,
      values,
    }: {
      setFieldValue: ((field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonAddInput>>);
      values: IngestionJsonAddInput;
    },
  ) => {
    const hasUserChoiceJsonMapperRepresentations = resolveHasUserChoiceJsonMapper(option);
    setHasUserChoiceJsonMapper(hasUserChoiceJsonMapperRepresentations);
    await updateObjectMarkingField(setFieldValue, values);
  };
  const ingestionJsonCreationValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    json_mapper_id: Yup.object().required(t_i18n('This field is required')),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.object().nullable(),
  });

  const [commit] = useApiMutation(ingestionJsonCreationMutation);
  const onSubmit: FormikConfig<IngestionJsonAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    let authenticationValue = isDuplicated ? ingestionJsonData?.authentication_value : values.authentication_value;
    if (values.authentication_type === 'basic') {
      authenticationValue = `${values.username}:${values.password}`;
    } else if (values.authentication_type === 'certificate') {
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
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_ingestionJsons',
          paginationOptions,
          'ingestionJsonAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        setIsCreateDisabled(true);
        resetForm();
      },
    });
  };
  const queryRef = useQueryLoading<JsonMapperFieldSearchQuery>(jsonMapperQuery);
  const initialValues: IngestionJsonAddInput = isDuplicated && ingestionJsonData ? {
    name: `${ingestionJsonData.name} - copy`,
    description: ingestionJsonData.description,
    scheduling_period: ingestionJsonData.scheduling_period ?? 'auto',
    uri: ingestionJsonData.uri,
    verb: ingestionJsonData.verb ?? 'GET',
    body: ingestionJsonData.body ?? '',
    headers: (ingestionJsonData.headers ?? []) as IngestionJsonHeader[],
    query_attributes: (ingestionJsonData.query_attributes ?? []) as IngestionJsonAttributes[],
    pagination_with_sub_page: ingestionJsonData.pagination_with_sub_page ?? false,
    pagination_with_sub_page_query_verb: ingestionJsonData.pagination_with_sub_page_query_verb ?? '',
    pagination_with_sub_page_attribute_path: ingestionJsonData.pagination_with_sub_page_attribute_path ?? '',
    json_mapper_id: convertMapper(ingestionJsonData, 'jsonMapper'),
    authentication_type: ingestionJsonData.authentication_type,
    authentication_value: ingestionJsonData.authentication_value,
    ingestion_running: ingestionJsonData.ingestion_running,
    user_id: convertUser(ingestionJsonData, 'user'),
    username: ingestionJsonData.authentication_type === BASIC_AUTH ? extractUsername(ingestionJsonData.authentication_value) : undefined,
    password: ingestionJsonData.authentication_type === BASIC_AUTH ? extractPassword(ingestionJsonData.authentication_value) : undefined,
    cert: ingestionJsonData.authentication_type === CERT_AUTH ? extractCert(ingestionJsonData.authentication_value) : undefined,
    key: ingestionJsonData.authentication_type === CERT_AUTH ? extractKey(ingestionJsonData.authentication_value) : undefined,
    ca: ingestionJsonData.authentication_type === CERT_AUTH ? extractCA(ingestionJsonData.authentication_value) : undefined,
    markings: me.allowed_marking?.filter(
      (marking) => ingestionJsonData.markings?.includes(marking.id),
    ).map((marking) => ({
      label: marking.definition ?? '',
      value: marking.id,
    })) ?? [],
  } : {
    name: '',
    description: '',
    scheduling_period: 'auto',
    uri: '',
    body: '',
    verb: 'GET',
    pagination_with_sub_page: false,
    pagination_with_sub_page_query_verb: 'GET',
    pagination_with_sub_page_attribute_path: '',
    headers: [],
    query_attributes: [],
    json_mapper_id: '',
    authentication_type: 'none',
    authentication_value: '',
    user_id: '',
    username: '',
    password: '',
    cert: '',
    key: '',
    ca: '',
    markings: [],
  };

  return (
    <Formik<IngestionJsonAddInput>
      initialValues={initialValues}
      validationSchema={ingestionJsonCreationValidation}
      onSubmit={onSubmit}
      onReset={handleClose}
    >
      {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => (
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
            values={values.query_attributes}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <HeaderFieldAdd
            id="headers"
            name="headers"
            values={values.headers}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <Alert severity="info" variant="standard" style={{ position: 'relative', marginTop: 20, marginBottom: 20, padding: '0px 10px 10px 10px' }}>
            <div>
              {t_i18n('For specific api (like Trino), sometimes it required to have sub pagination. To activate only for this specific use cases')}
            </div>
            <Box sx={{ display: 'flex', alignItems: 'center', marginTop: '20px' }}>
              <FormControlLabel
                control={<Switch />}
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
            onChange={(_, option) => onCreatorSelection(option)}
            showConfidence
          />
          {
            queryRef && (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
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
                  onChange={(_, option) => onJsonMapperSelection(option, { setFieldValue, values })}
                  isOptionEqualToValue={(option: FieldOption, { value }: FieldOption) => option.value === value}
                  queryRef={queryRef}
                />
              </React.Suspense>
            )
          }
          {
            hasUserChoiceJsonMapper && (
              <ObjectMarkingField
                name="markings"
                label={t_i18n('Marking definition levels')}
                style={fieldSpacingContainerStyle}
                allowedMarkingOwnerId={isGranted ? creatorId : undefined}
                setFieldValue={setFieldValue}
              />
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
          >
            <MenuItem value="none">{t_i18n('None')}</MenuItem>
            <MenuItem value="basic">
              {t_i18n('Basic user / password')}
            </MenuItem>
            <MenuItem value="bearer">{t_i18n('Bearer token')}</MenuItem>
            <MenuItem value="certificate">
              {t_i18n('Client certificate')}
            </MenuItem>
          </Field>
          {values.authentication_type === 'basic' && (
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
              />
            </>
          )}
          {values.authentication_type === 'bearer' && (
            <PasswordTextField
              name="authentication_value"
              label={t_i18n('Token')}
            />
          )}
          {values.authentication_type === 'certificate' && (
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
          <Box sx={{ width: '100%', marginTop: 5 }}>
            <Alert
              severity="info"
              variant="outlined"
              style={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('Please, verify the validity of the selected JSON mapper for the given URL.')}<br />
              {t_i18n('Only successful tests allow the ingestion creation.')}
            </Alert>
          </Box>
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
              color={isCreateDisabled ? 'secondary' : 'primary'}
              onClick={() => setOpen(true)}
              classes={{ root: classes.button }}
              disabled={!(values.uri && values.json_mapper_id)}
            >
              {t_i18n('Verify')}
            </Button>
            {isDuplicated ? (
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting || isCreateDisabled}
                classes={{ root: classes.button }}
              >
                {t_i18n('Duplicate')}
              </Button>
            ) : (
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting || isCreateDisabled}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create')}
              </Button>
            )}
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

const CreateIngestionJsonControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="IngestionJson"
    {...props}
  />
);

export const IngestionJsonCreationContainer: FunctionComponent<IngestionJsonCreationContainerProps> = ({
  queryRef,
  handleClose,
  open,
  paginationOptions,
  isDuplicated,
}) => {
  const { t_i18n } = useFormatter();

  const ingestionJson = queryRef
    ? usePreloadedQuery(ingestionJsonEditionContainerQuery, queryRef).ingestionJson
    : null;
  return (
    <Drawer
      title={isDuplicated ? t_i18n('Duplicate a JSON feed') : t_i18n('Create a JSON feed')}
      open={open}
      onClose={handleClose}
      controlledDial={!isDuplicated ? CreateIngestionJsonControlledDial : undefined}
    >
      {({ onClose }) => (
        <IngestionJsonCreation
          ingestionJson={ingestionJson}
          handleClose={onClose}
          paginationOptions={paginationOptions}
          isDuplicated={isDuplicated}
        />
      )}
    </Drawer>
  );
};
