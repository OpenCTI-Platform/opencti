import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import { Option } from '@components/common/form/ReferenceField';
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
import Button from '@mui/material/Button';
import IngestionJsonMapperTestDialog from '@components/data/ingestionJson/IngestionJsonMapperTestDialog';
import makeStyles from '@mui/styles/makeStyles';
import { IngestionJsonEditionFragment_ingestionJson$key } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionFragment_ingestionJson.graphql';
import { JsonMapperFieldSearchQuery } from '@components/common/form/__generated__/JsonMapperFieldSearchQuery.graphql';
import { QueryAttributeFieldAdd } from '@components/common/form/QueryAttributeField';
import { HeaderFieldAdd } from '@components/common/form/HeaderField';
import { convertMapper, convertUser } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { adaptFieldValue } from '../../../../utils/String';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import { USER_CHOICE_MARKING_CONFIG } from '../../../../utils/csvMapperUtils';
import { BASIC_AUTH, BEARER_AUTH, CERT_AUTH, extractCA, extractCert, extractKey, extractPassword, extractUsername } from '../../../../utils/ingestionAuthentificationUtils';
import PasswordTextField from '../../../../components/PasswordTextField';

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

export const ingestionJsonEditionPatch = graphql`
  mutation IngestionJsonEditionPatchMutation($id: ID!, $input: [EditInput!]!) {
    ingestionJsonFieldPatch(id: $id, input: $input) {
      ...IngestionJsonEditionFragment_ingestionJson
    }
  } 
`;

export const ingestionJsonEditionFragment = graphql`
  fragment IngestionJsonEditionFragment_ingestionJson on IngestionJson {
    id
    name
    description
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
  enableReferences?: boolean
}

interface IngestionJsonEditionForm {
  message?: string | null
  references?: ExternalReferencesValues
  name: string,
  description?: string | null,
  uri: string,
  authentication_type: string,
  authentication_value?: string | null,
  ingestion_running?: boolean | null,
  json_mapper_id: string | Option,
  user_id: string | Option,
  markings: Option[],
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
  const classes = useStyles();
  const [open, setOpen] = useState(false);
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
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    json_mapper_id: Yup.mixed().required(t_i18n('This field is required')),
    markings: Yup.array().required(),
  };

  const ingestionJsonValidator = useSchemaEditionValidation('IngestionJson', basicShape);
  const [commitUpdate] = useApiMutation(ingestionJsonEditionPatch);

  const onSubmit: FormikConfig<IngestionJsonEditionForm>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    commitUpdate({
      variables: {
        id: ingestionJsonData.id,
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
    value: Option | Option[] | JsonMapperFieldOption | string | string[] | number | number[] | null,
  ) => {
    let finalValue = value as string;
    let finalName = name;

    // region authentication -- If you change something here, please have a look at IngestionTaxiiEdition
    const backendAuthValue = ingestionJsonData.authentication_value;
    // re-compose username:password
    if (name === 'username') {
      finalName = 'authentication_value';
      finalValue = `${value}:${extractPassword(backendAuthValue)}`;
    }

    if (name === 'password') {
      finalName = 'authentication_value';
      finalValue = `${extractUsername(backendAuthValue)}:${value}`;
    }

    // re-compose cert:key:ca
    if (name === 'cert') {
      finalName = 'authentication_value';
      finalValue = `${value}:${extractKey(backendAuthValue)}:${extractCA(backendAuthValue)}`;
    }

    if (name === 'key') {
      finalName = 'authentication_value';
      finalValue = `${extractCert(backendAuthValue)}:${value}:${extractCA(backendAuthValue)}`;
    }

    if (name === 'ca') {
      finalName = 'authentication_value';
      finalValue = `${extractCert(backendAuthValue)}:${extractKey(backendAuthValue)}:${value}`;
    }
    // end region authentication

    if (name === 'json_mapper_id' || name === 'user_id') {
      finalValue = (value as Option).value;
    }
    // if (name === 'json_mapper_id') {
    //   const hasUserChoiceJsonMapperRepresentations = resolveHasUserChoiceJsonMapper(value as JsonMapperFieldOption);
    //   setHasUserChoiceJsonMapper(hasUserChoiceJsonMapperRepresentations);
    // }
    // if (name === 'user_id') {
    //   onCreatorSelection(value as Option).then();
    // }
    ingestionJsonValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: ingestionJsonData.id,
            input: [{ key: finalName, value: finalValue || '' }],
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = {
    name: ingestionJsonData.name,
    description: ingestionJsonData.description,
    uri: ingestionJsonData.uri,
    verb: ingestionJsonData.verb,
    headers: ingestionJsonData.headers,
    query_attributes: ingestionJsonData.query_attributes,
    authentication_type: ingestionJsonData.authentication_type,
    authentication_value: ingestionJsonData.authentication_type === BEARER_AUTH ? ingestionJsonData.authentication_value : undefined,
    username: ingestionJsonData.authentication_type === BASIC_AUTH ? extractUsername(ingestionJsonData.authentication_value) : undefined,
    password: ingestionJsonData.authentication_type === BASIC_AUTH ? extractPassword(ingestionJsonData.authentication_value) : undefined,
    cert: ingestionJsonData.authentication_type === CERT_AUTH ? extractCert(ingestionJsonData.authentication_value) : undefined,
    key: ingestionJsonData.authentication_type === CERT_AUTH ? extractKey(ingestionJsonData.authentication_value) : undefined,
    ca: ingestionJsonData.authentication_type === CERT_AUTH ? extractCA(ingestionJsonData.authentication_value) : undefined,
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
  };

  const queryRef = useQueryLoading<JsonMapperFieldSearchQuery>(jsonMapperQuery);

  const defaultMarkingOptions = (me.default_marking?.flatMap(({ values }) => (values ?? [{ id: '', definition: '' }])?.map(({ id, definition }) => ({ label: definition, value: id }))) ?? []) as Option[];
  const updateJsonMapper = async (
    setFieldValue: (field: string, option: Option, shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonEditionForm>>,
    option: JsonMapperFieldOption,
  ) => {
    await setFieldValue('json_mapper_id', option);
  };
  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: Option[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionJsonEditionForm>>,
    values: IngestionJsonEditionForm,
    newHasUserChoiceJsonMapper: boolean,
  ) => {
    const markings = newHasUserChoiceJsonMapper ? values.markings : defaultMarkingOptions;
    await setFieldValue('markings', markings);
    handleSubmitField('markings', markings.map(({ value }: Option) => value));
  };
  return (
    <Formik<IngestionJsonEditionForm>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={ingestionJsonValidator}
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
        <Form>
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
          <Field
            component={TextField}
            variant="standard"
            name="uri"
            label={t_i18n('HTTP JSON URL')}
            fullWidth={true}
            onSubmit={handleSubmitField}
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
            <MenuItem value="GET">{t_i18n('Get')}</MenuItem>
            <MenuItem value="POST">{t_i18n('Post')}</MenuItem>
          </Field>

          <QueryAttributeFieldAdd
            id="query_attributes"
            name="query_attributes"
            values={values?.query_attributes}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />

          <HeaderFieldAdd
            id="headers"
            name="headers"
            values={values?.headers}
            containerStyle={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />

          <CreatorField
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            onChange={handleSubmitField}
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
                    {t_i18n('Depending on the selected JSON mapper configurations, marking definition levels can be set in the dedicated field.')}<br/>
                    <br/>
                    {t_i18n('If the JSON mapper is configured with "Use default markings definitions of the user", the default markings of the user responsible for data creation are applied to the ingested entities. Otherwise, you can choose markings to apply.')}<br/>
                  </Alert>
                </Box>
                <JsonMapperField
                  name="json_mapper_id"
                  isOptionEqualToValue={(option: Option, value: Option) => option.value === value.value }
                  onChange={async (_, option) => {
                    handleSubmitField('json_mapper_id', option);
                    await updateJsonMapper(setFieldValue, option);
                    const hasUserChoiceJsonMapperRepresentations = resolveHasUserChoiceJsonMapper(option as JsonMapperFieldOption);
                    await updateObjectMarkingField(setFieldValue, values, hasUserChoiceJsonMapperRepresentations);
                  }}
                  queryRef={queryRef}
                />
              </React.Suspense>
            )
          }
          {
            // hasUserChoiceJsonMapper && (
            //   <ObjectMarkingField
            //     name="markings"
            //     isOptionEqualToValue={(option: Option, value: Option) => option.value === value.value}
            //     label={t_i18n('Marking definition levels')}
            //     style={fieldSpacingContainerStyle}
            //     allowedMarkingOwnerId={isGranted ? creatorId : undefined}
            //     setFieldValue={setFieldValue}
            //     onChange={(name, value) => {
            //       if (value.length) {
            //         handleSubmitField(name, value.map((marking) => marking.value));
            //       }
            //     }}
            //   />
            // )
          }
          <Field
            component={SelectField}
            variant="standard"
            name="authentication_type"
            label={t_i18n('Authentication type')}
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
                onSubmit={handleSubmitField}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="password"
                label={t_i18n('Password')}
                onSubmit={handleSubmitField}
              />
            </>
          )}
          {values.authentication_type === BEARER_AUTH && (
            <PasswordTextField
              name="authentication_value"
              label={t_i18n('Token')}
              onSubmit={handleSubmitField}
            />
          )}
          {values.authentication_type === CERT_AUTH && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="cert"
                label={t_i18n('Certificate (base64)')}
                onSubmit={handleSubmitField}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="key"
                label={t_i18n('Key (base64)')}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                name="ca"
                label={t_i18n('CA certificate (base64)')}
                onSubmit={handleSubmitField}
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
              {t_i18n('Please, verify the validity of the selected JSON mapper for the given URL.')}<br/>
              {t_i18n('Only successful tests allow the ingestion edition.')}
            </Alert>
          </Box>
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="secondary"
              onClick={() => setOpen(true)}
              classes={{ root: classes.button }}
              disabled={!(values.uri && values.json_mapper_id)}
            >
              {t_i18n('Verify')}
            </Button>
          </div>
          <IngestionJsonMapperTestDialog
            open={open}
            onClose={() => setOpen(false)}
            values={values}
          />
        </Form>
      )}
    </Formik>
  );
};

export default IngestionJsonEdition;
