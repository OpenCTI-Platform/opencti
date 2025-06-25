import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik, FormikErrors } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { IngestionAuthType, IngestionCsvMapperType } from '@components/data/ingestionCsv/__generated__/IngestionCsvCreationMutation.graphql';
import CsvMapperField, { csvMapperQuery } from '@components/common/form/CsvMapperField';
import IngestionCsvFeedTestDialog from '@components/data/ingestionCsv/IngestionCsvFeedTestDialog';
import { CsvMapperFieldSearchQuery } from '@components/common/form/__generated__/CsvMapperFieldSearchQuery.graphql';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { ingestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/IngestionCsvEditionContainer';
import { ingestionCsvEditionFragment } from '@components/data/ingestionCsv/IngestionCsvEdition';
import {
  IngestionCsvEditionFragment_ingestionCsv$data,
  IngestionCsvEditionFragment_ingestionCsv$key,
} from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
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
import { CsvMapperAddInput } from '../csvMapper/CsvMapperUtils';

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

const initCSVCreateForm: IngestionCsvAddInput = {
  name: '',
  description: '',
  uri: '',
  csv_mapper_id: '',
  scheduling_period: 'PT1H',
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

const ingestionCsvCreationMutation = graphql`
  mutation IngestionCsvCreationDeprecatedMutation($input: IngestionCsvAddInput!) {
    ingestionCsvAdd(input: $input) {
      ...IngestionCsvLine_node
    }
  }
`;

interface IngestionCsvCreationProps {
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables | null | undefined;
  handleClose?: () => void;
  ingestionCsvData?: IngestionCsvEditionFragment_ingestionCsv$data | null;
  triggerButton?: boolean;
  drawerSettings?: {
    title: string;
    button: string;
  }
}

interface IngestionCsvCreationContainerProps extends IngestionCsvCreationProps {
  queryRef?: PreloadedQuery<IngestionCsvEditionContainerQuery>,
  open?: boolean,

}

export interface IngestionCsvAddInput {
  name: string
  message?: string | null
  references?: ExternalReferencesValues
  description?: string | null
  scheduling_period?: string | null
  uri: string
  csv_mapper_type?: IngestionCsvMapperType
  csv_mapper?: CsvMapperAddInput
  csv_mapper_id?: string | FieldOption
  authentication_type: IngestionAuthType | string
  authentication_value?: string | null
  ingestion_running?: boolean | null
  user_id: string | FieldOption
  username?: string
  password?: string
  cert?: string
  key?: string
  ca?: string
  markings: FieldOption[]
}

const resolveHasUserChoiceCsvMapper = (option: FieldOption & {
  representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[]
}) => {
  return option.representations.some(
    (representation) => representation.attributes.some(
      (attribute) => attribute.key === 'objectMarking' && attribute.default_values.some(
        ((value) => (typeof value === 'string' ? value === USER_CHOICE_MARKING_CONFIG : value?.name === USER_CHOICE_MARKING_CONFIG)),
      ),
    ),
  );
};

const CreateIngestionCsvControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType='IngestionCsv'
    {...props}
  />
);

const IngestionCsvCreation: FunctionComponent<IngestionCsvCreationProps> = ({ paginationOptions, handleClose, ingestionCsvData, drawerSettings }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const isGranted = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const { me } = useAuth();
  const [open, setOpen] = useState(false);
  const [isCreateDisabled, setIsCreateDisabled] = useState(true);
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(false);
  const [creatorId, setCreatorId] = useState('');

  const onCreatorSelection = async (option: FieldOption) => {
    setCreatorId(option.value);
  };
  const updateObjectMarkingField = async (
    setFieldValue: (field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvAddInput>>,
    values: IngestionCsvAddInput,
  ) => {
    await setFieldValue('markings', values.markings);
  };
  const onCsvMapperSelection = async (
    option: FieldOption & {
      representations: { attributes: { key: string; default_values: { name: string }[] | string[] }[] }[]
    },
    {
      setFieldValue,
      values,
    }:{
      setFieldValue: ((field: string, value: FieldOption[], shouldValidate?: boolean) => Promise<void | FormikErrors<IngestionCsvAddInput>>);
      values: IngestionCsvAddInput
    },
  ) => {
    const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceCsvMapper(option);
    setHasUserChoiceCsvMapper(hasUserChoiceCsvMapperRepresentations);
    await updateObjectMarkingField(setFieldValue, values);
  };
  const ingestionCsvCreationValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    csv_mapper_type: Yup.string(),
    csv_mapper: Yup.string(),
    csv_mapper_id: Yup.object(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.object().nullable(),
  });

  const [commit] = useApiMutation(ingestionCsvCreationMutation);
  const onSubmit: FormikConfig<IngestionCsvAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    let authenticationValue = ingestionCsvData?.authentication_value ?? values.authentication_value;
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
      csv_mapper_id: typeof values.csv_mapper_id === 'string' ? values.csv_mapper_id : values.csv_mapper_id?.value,
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
  const initialValues: IngestionCsvAddInput = ingestionCsvData ? {
    ...ingestionCsvData,
    name: `${ingestionCsvData.name}`,
    scheduling_period: ingestionCsvData.scheduling_period ?? 'PT1H',
    csv_mapper_type: 'id',
    csv_mapper: undefined,
    csv_mapper_id: convertMapper(ingestionCsvData, 'csvMapper'),
    user_id: convertUser(ingestionCsvData, 'user'),
    username: ingestionCsvData.authentication_type === BASIC_AUTH ? extractUsername(ingestionCsvData.authentication_value) : undefined,
    password: ingestionCsvData.authentication_type === BASIC_AUTH ? extractPassword(ingestionCsvData.authentication_value) : undefined,
    cert: ingestionCsvData.authentication_type === CERT_AUTH ? extractCert(ingestionCsvData.authentication_value) : undefined,
    key: ingestionCsvData.authentication_type === CERT_AUTH ? extractKey(ingestionCsvData.authentication_value) : undefined,
    ca: ingestionCsvData.authentication_type === CERT_AUTH ? extractCA(ingestionCsvData.authentication_value) : undefined,
    markings: me.allowed_marking?.filter(
      (marking) => ingestionCsvData.markings?.includes(marking.id),
    ).map((marking) => ({
      label: marking.definition ?? '',
      value: marking.id,
    })) ?? [],
  } : initCSVCreateForm;

  return (
    <Formik<IngestionCsvAddInput>
      initialValues={initialValues}
      validationSchema={ingestionCsvCreationValidation}
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
          <IngestionSchedulingField/>
          <Field
            component={TextField}
            variant="standard"
            name="uri"
            label={t_i18n('CSV URL')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <CreatorField
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            containerStyle={fieldSpacingContainerStyle}
            onChange={(_, option) => onCreatorSelection(option)}
            showConfidence
          />
          {
            queryRef && (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
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
                  onChange={(_, option) => onCsvMapperSelection(option, { setFieldValue, values })}
                  isOptionEqualToValue={(option: FieldOption, { value }: FieldOption) => option.value === value}
                  queryRef={queryRef}
                />
              </React.Suspense>
            )
          }
          {
            hasUserChoiceCsvMapper && (
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
              {drawerSettings?.button ?? t_i18n('Create')}
            </Button>

          </div>
          <IngestionCsvFeedTestDialog
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
export const IngestionCsvCreationContainerDeprecated: FunctionComponent<IngestionCsvCreationContainerProps> = ({
  queryRef,
  handleClose,
  open = false,
  paginationOptions,
  drawerSettings,
  ingestionCsvData,
  triggerButton = true,
}) => {
  const { t_i18n } = useFormatter();

  const ingestionCsv = queryRef
    ? usePreloadedQuery(ingestionCsvEditionContainerQuery, queryRef).ingestionCsv
    : null;
  const ingestionCsvDataRef = ingestionCsv ? useFragment<IngestionCsvEditionFragment_ingestionCsv$key>(ingestionCsvEditionFragment, ingestionCsv) : null;
  const duplicateCsvData = ingestionCsvDataRef ? {
    ...ingestionCsvDataRef,
    name: `${ingestionCsvDataRef.name} - copy`,
  } as IngestionCsvEditionFragment_ingestionCsv$data : null;
  return (
    <Drawer
      title={drawerSettings?.title ?? t_i18n('Create a CSV Feed')}
      open={open}
      onClose={handleClose}
      controlledDial={triggerButton ? CreateIngestionCsvControlledDial : undefined}
    >
      {({ onClose }) => (
        <IngestionCsvCreation
          ingestionCsvData={ingestionCsvData || duplicateCsvData || undefined}
          handleClose={onClose}
          paginationOptions={paginationOptions}
          drawerSettings={drawerSettings}
        />
      )}
    </Drawer>
  );
};
