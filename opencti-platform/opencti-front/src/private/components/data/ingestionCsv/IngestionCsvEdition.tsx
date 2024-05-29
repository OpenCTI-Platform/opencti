import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import { Option } from '@components/common/form/ReferenceField';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CreatorField from '@components/common/form/CreatorField';
import CommitMessage from '@components/common/form/CommitMessage';
import { IngestionCsvEditionFragment_ingestionCsv$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import CsvMapperField, { csvMapperQuery } from '@components/common/form/CsvMapperField';
import Button from '@mui/material/Button';
import IngestionCsvMapperTestDialog from '@components/data/ingestionCsv/IngestionCsvMapperTestDialog';
import makeStyles from '@mui/styles/makeStyles';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import { convertMapper, convertUser } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { adaptFieldValue } from '../../../../utils/String';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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

const ingestionCsvEditionFragment = graphql`
  fragment IngestionCsvEditionFragment_ingestionCsv on IngestionCsv {
    id
    name
    description
    uri
    authentication_type
    authentication_value
    ingestion_running
    current_state_date
    csvMapper {
      id
      name
    }
    user {
      id
      entity_type
      name
    }
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
  current_state_date: Date | null
  ingestion_running?: boolean | null,
  csv_mapper_id: string | Option,
  user_id: string | Option
}

const IngestionCsvEdition: FunctionComponent<IngestionCsvEditionProps> = ({
  ingestionCsv,
  handleClose,
  enableReferences = false,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const ingestionCsvData = useFragment(ingestionCsvEditionFragment, ingestionCsv);
  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    current_state_date: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    user_id: Yup.mixed().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    csv_mapper_id: Yup.mixed().required(t_i18n('This field is required')),
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

  const handleSubmitField = (name: string, value: Option | string | string[] | number | number[] | null) => {
    let finalValue = value as string;
    if (name === 'csv_mapper_id' || name === 'user_id') {
      finalValue = (value as Option).value;
    }
    ingestionCsvValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: ingestionCsvData.id,
            input: { key: name, value: finalValue || '' },
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
    authentication_value: ingestionCsvData.authentication_value,
    current_state_date: ingestionCsvData.current_state_date,
    ingestion_running: ingestionCsvData.ingestion_running,
    csv_mapper_id: convertMapper(ingestionCsvData, 'csvMapper'),
    user_id: convertUser(ingestionCsvData, 'user'),
    references: undefined,
  };

  const queryRef = useQueryLoading<CsvMapperFieldSearchQuery>(csvMapperQuery);

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
        <Form style={{ margin: '20px 0 20px 0' }}>
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
          <Field
            component={DateTimePickerField}
            name="current_state_date"
            textFieldProps={{
              label: t_i18n(
                'Import from date (empty = all CSV feed possible items)',
              ),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          {
            queryRef && (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                <CsvMapperField
                  name="csv_mapper_id"
                  isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value}
                  onChange={handleSubmitField}
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
          {values.authentication_type === 'basic' && (
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
              <Field
                component={TextField}
                variant="standard"
                name="password"
                label={t_i18n('Password')}
                onSubmit={handleSubmitField}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
            </>
          )}
          {values.authentication_type === 'bearer' && (
            <Field
              component={TextField}
              variant="standard"
              name="authentication_value"
              label={t_i18n('Token')}
              onSubmit={handleSubmitField}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
          )}
          {values.authentication_type === 'certificate' && (
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
              <Field
                component={TextField}
                variant="standard"
                name="key"
                label={t_i18n('Key (base64)')}
                onSubmit={handleSubmitField}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
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
          <CreatorField
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            onChange={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
            showConfidence
          />
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
