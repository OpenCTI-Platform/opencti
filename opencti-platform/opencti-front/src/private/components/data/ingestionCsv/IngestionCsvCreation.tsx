import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { CsvAuthType } from '@components/data/ingestionCsv/__generated__/IngestionCsvCreationMutation.graphql';
import CsvMapperField, { csvMapperQuery } from '@components/common/form/CsvMapperField';
import IngestionCsvMapperTestDialog from '@components/data/ingestionCsv/IngestionCsvMapperTestDialog';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import SelectField from '../../../../components/fields/SelectField';
import type { Theme } from '../../../../components/Theme';
import DateTimePickerField from '../../../../components/DateTimePickerField';
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

const ingestionCsvCreationMutation = graphql`
  mutation IngestionCsvCreationMutation($input: IngestionCsvAddInput!) {
    ingestionCsvAdd(input: $input) {
      ...IngestionCsvLine_node
    }
  }
`;

interface IngestionCsvCreationProps {
  paginationOptions: IngestionCsvLinesPaginationQuery$variables;
}

export interface IngestionCsvCreationForm {
  name: string
  description: string
  uri: string
  csv_mapper_id: string | Option
  authentication_type: CsvAuthType
  authentication_value: string
  current_state_date: Date | null
  user_id: string | Option
  username?: string
  password?: string
  cert?: string
  key?: string
  ca?: string
}

const IngestionCsvCreation: FunctionComponent<IngestionCsvCreationProps> = ({ paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [isCreateDisabled, setIsCreateDisabled] = useState(true);

  const ingestionCsvCreationValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    current_state_date: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    csv_mapper_id: Yup.object().required(t_i18n('This field is required')),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.object().nullable(),
  });

  const [commit] = useApiMutation(ingestionCsvCreationMutation);
  const onSubmit: FormikConfig<IngestionCsvCreationForm>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    let authenticationValue = values.authentication_value;
    if (values.authentication_type === 'basic') {
      authenticationValue = `${values.username}:${values.password}`;
    } else if (values.authentication_type === 'certificate') {
      authenticationValue = `${values.cert}:${values.key}:${values.ca}`;
    }
    const input = {
      name: values.name,
      description: values.description,
      uri: values.uri,
      csv_mapper_id: typeof values.csv_mapper_id === 'string' ? values.csv_mapper_id : values.csv_mapper_id.value,
      authentication_type: values.authentication_type,
      authentication_value: authenticationValue,
      current_state_date: values.current_state_date,
      user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id.value,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_ingestionCsvs',
          paginationOptions,
          'ingestionCsvAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        setIsCreateDisabled(true);
        resetForm();
      },
    });
  };

  const queryRef = useQueryLoading<CsvMapperFieldSearchQuery>(csvMapperQuery);

  return (
    <Drawer
      title={t_i18n('Create a CSV ingester')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik<IngestionCsvCreationForm>
          initialValues={{
            name: '',
            description: '',
            uri: '',
            csv_mapper_id: '',
            authentication_type: 'none',
            authentication_value: '',
            current_state_date: null,
            user_id: '',
            username: '',
            password: '',
            cert: '',
            key: '',
            ca: '',
          }}
          validationSchema={ingestionCsvCreationValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
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
              <Field
                component={DateTimePickerField}
                name="current_state_date"
                textFieldProps={{
                  label: t_i18n('Import from date (empty = all Csv possible items)'),
                  variant: 'standard',
                  fullWidth: true,
                  style: fieldSpacingContainerStyle,
                }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t_i18n('CSV URL')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              {
                queryRef && (
                  <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                    <CsvMapperField
                      name="csv_mapper_id"
                      isOptionEqualToValue={(option: Option, { value }: Option) => option.value === value}
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
                  <Field
                    component={TextField}
                    variant="standard"
                    name="password"
                    label={t_i18n('Password')}
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
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="key"
                    label={t_i18n('Key (base64)')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
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
              <CreatorField
                name="user_id"
                label={t_i18n('User responsible for data creation (empty = System)')}
                containerStyle={fieldSpacingContainerStyle}
                showConfidence
              />
              <Box sx={{ width: '100%', marginTop: 5 }}>
                <Alert
                  severity="info"
                  variant="outlined"
                  style={{ padding: '0px 10px 0px 10px' }}
                >
                  {t_i18n('Please, verify the validity of the selected CSV mapper for the given URL.')}<br/>
                  {t_i18n('Only successful tests allow the ingestion creation.')}
                </Alert>
              </Box>
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color={isCreateDisabled ? 'secondary' : 'primary'}
                  onClick={() => setOpen(true)}
                  classes={{ root: classes.button }}
                  disabled={!(values.uri && values.csv_mapper_id)}
                >
                  {t_i18n('Verify')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting || isCreateDisabled}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
              <IngestionCsvMapperTestDialog
                open={open}
                onClose={() => setOpen(false)}
                values={values}
                setIsCreateDisabled={setIsCreateDisabled}
              />
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default IngestionCsvCreation;
