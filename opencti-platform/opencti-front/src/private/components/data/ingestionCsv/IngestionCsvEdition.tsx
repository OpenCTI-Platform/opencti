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
import { IngestionCsvEditionFragment_ingestionCsv$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import CsvMapperField, { CsvMapperFieldOption, csvMapperQuery } from '@components/common/form/CsvMapperField';
import Button from '@mui/material/Button';
import IngestionCsvMapperTestDialog from '@components/data/ingestionCsv/IngestionCsvMapperTestDialog';
import makeStyles from '@mui/styles/makeStyles';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
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
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
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
    uri
    authentication_type
    authentication_value
    ingestion_running
    csvMapper {
      id
      name
      representations {
        attributes {
          key
          default_values {
            name
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
  }
`;

interface IngestionCsvEditionProps {
  ingestionCsv: IngestionCsvEditionFragment_ingestionCsv$key;
  handleClose: () => void;
  enableReferences?: boolean
}

interface IngestionCsvEditionForm {
  message?: string | null
  references?: ExternalReferencesValues
  name: string,
  description?: string | null,
  uri: string,
  authentication_type: string,
  authentication_value?: string | null,
  ingestion_running?: boolean | null,
  csv_mapper_id: string | Option,
  user_id: string | Option,
  markings: Option[],
}

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
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const ingestionCsvData = useFragment(ingestionCsvEditionFragment, ingestionCsv);
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(ingestionCsvData.csvMapper.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && (attribute.default_values && attribute.default_values?.some(
        (value: string | { name: string }) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value.name === USER_CHOICE_MARKING_CONFIG),
      )),
    ),
  ));
  const [creatorId, setCreatorId] = useState(ingestionCsvData.user?.id);
  const isGranted = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const onCreatorSelection = async (option: Option) => {
    setCreatorId(option.value);
  };
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
    csv_mapper_id: Yup.mixed().required(t_i18n('This field is required')),
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
    value: Option | Option[] | CsvMapperFieldOption | string | string[] | number | number[] | null,
  ) => {
    let finalValue = value as string;
    let finalName = name;

    // region authentication -- If you change something here, please have a look at IngestionTaxiiEdition
    const backendAuthValue = ingestionCsvData.authentication_value;
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

    if (name === 'csv_mapper_id' || name === 'user_id') {
      finalValue = (value as Option).value;
    }
    if (name === 'csv_mapper_id') {
      const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceCsvMapper(value as CsvMapperFieldOption);
      setHasUserChoiceCsvMapper(hasUserChoiceCsvMapperRepresentations);
    }
    if (name === 'user_id') {
      onCreatorSelection(value as Option).then();
    }
    ingestionCsvValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: ingestionCsvData.id,
            input: [{ key: finalName, value: finalValue || '' }],
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = {
    name: ingestionCsvData.name,
    description: ingestionCsvData.description,
    uri: ingestionCsvData.uri,
    authentication_type: ingestionCsvData.authentication_type,
    authentication_value: ingestionCsvData.authentication_type === BEARER_AUTH ? ingestionCsvData.authentication_value : undefined,
    username: ingestionCsvData.authentication_type === BASIC_AUTH ? extractUsername(ingestionCsvData.authentication_value) : undefined,
    password: ingestionCsvData.authentication_type === BASIC_AUTH ? extractPassword(ingestionCsvData.authentication_value) : undefined,
    cert: ingestionCsvData.authentication_type === CERT_AUTH ? extractCert(ingestionCsvData.authentication_value) : undefined,
    key: ingestionCsvData.authentication_type === CERT_AUTH ? extractKey(ingestionCsvData.authentication_value) : undefined,
    ca: ingestionCsvData.authentication_type === CERT_AUTH ? extractCA(ingestionCsvData.authentication_value) : undefined,
    ingestion_running: ingestionCsvData.ingestion_running,
    csv_mapper_id: convertMapper(ingestionCsvData, 'csvMapper'),
    user_id: convertUser(ingestionCsvData, 'user'),
    references: undefined,
    markings: me.allowed_marking?.filter(
      (marking) => ingestionCsvData.markings?.includes(marking.id),
    ).map((marking) => ({
      label: marking.definition ?? '',
      value: marking.id,
    })) ?? [],
  };

  const queryRef = useQueryLoading<CsvMapperFieldSearchQuery>(csvMapperQuery);

  const defaultMarkingOptions = (me.default_marking?.flatMap(({ values }) => (values ?? [{ id: '', definition: '' }])?.map(({ id, definition }) => ({ label: definition, value: id }))) ?? []) as Option[];
  const updateCsvMapper = async (
    setFieldValue: (field: string, option: Option, shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvEditionForm>>,
    option: CsvMapperFieldOption,
  ) => {
    await setFieldValue('csv_mapper_id', option);
  };
  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: Option[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvEditionForm>>,
    values: IngestionCsvEditionForm,
    newHasUserChoiceCsvMapper: boolean,
  ) => {
    const markings = newHasUserChoiceCsvMapper ? values.markings : defaultMarkingOptions;
    await setFieldValue('markings', markings);
    handleSubmitField('markings', markings.map(({ value }: Option) => value));
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
            label={t_i18n('CSV URL')}
            fullWidth={true}
            onSubmit={handleSubmitField}
            style={fieldSpacingContainerStyle}
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
                    {t_i18n('Depending on the selected CSV mapper configurations, marking definition levels can be set in the dedicated field.')}<br/>
                    <br/>
                    {t_i18n('If the CSV mapper is configured with "Use default markings definitions of the user", the default markings of the user responsible for data creation are applied to the ingested entities. Otherwise, you can choose markings to apply.')}<br/>
                  </Alert>
                </Box>
                <CsvMapperField
                  name="csv_mapper_id"
                  isOptionEqualToValue={(option: Option, value: Option) => option.value === value.value }
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
                isOptionEqualToValue={(option: Option, value: Option) => option.value === value.value}
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
              id={ingestionCsvData.id}
            />
          )}
          <Box sx={{ width: '100%', marginTop: 5 }}>
            <Alert
              severity="info"
              variant="outlined"
              style={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('Please, verify the validity of the selected CSV mapper for the given URL.')}<br/>
              {t_i18n('Only successful tests allow the ingestion edition.')}
            </Alert>
          </Box>
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="secondary"
              onClick={() => setOpen(true)}
              classes={{ root: classes.button }}
              disabled={!(values.uri && values.csv_mapper_id)}
            >
              {t_i18n('Verify')}
            </Button>
          </div>
          <IngestionCsvMapperTestDialog
            open={open}
            onClose={() => setOpen(false)}
            values={values}
          />
        </Form>
      )}
    </Formik>
  );
};

export default IngestionCsvEdition;
