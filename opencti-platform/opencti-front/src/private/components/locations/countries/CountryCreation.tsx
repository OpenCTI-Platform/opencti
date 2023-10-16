import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { Theme } from '../../../../components/Theme';
import { CountriesLinesPaginationQuery$variables } from './__generated__/CountriesLinesPaginationQuery.graphql';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { Option } from '../../common/form/ReferenceField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { CountryCreationMutation, CountryCreationMutation$variables } from './__generated__/CountryCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const countryMutation = graphql`
  mutation CountryCreationMutation($input: CountryAddInput!) {
    countryAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...CountryLine_node
    }
  }
`;

interface CountryAddInput {
  name: string;
  description: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  file: File | undefined;
}

interface CountryFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
}

const COUNTRY_TYPE = 'Country';

export const CountryCreationForm: FunctionComponent<CountryFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
  };
  const countryValidator = useSchemaCreationValidation(
    COUNTRY_TYPE,
    basicShape,
  );
  const [commit] = useMutation<CountryCreationMutation>(countryMutation);
  const onSubmit: FormikConfig<CountryAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input: CountryCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'countryAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };
  const initialValues = useDefaultValues<CountryAddInput>(COUNTRY_TYPE, {
    name: '',
    description: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });
  return (
    <Formik<CountryAddInput>
      initialValues={initialValues}
      validationSchema={countryValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Country']}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <CreatedByField
            name="createdBy"
            style={{
              marginTop: 20,
              width: '100%',
            }}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{
              marginTop: 20,
              width: '100%',
            }}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const CountryCreation = ({
  paginationOptions,
}: {
  paginationOptions: CountriesLinesPaginationQuery$variables;
}) => {
  const { t } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_countries', paginationOptions, 'countryAdd');
  return (
    <Drawer
      title={t('Create a country')}
      variant={DrawerVariant.create}
    >
      {({ onClose }) => (
        <CountryCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default CountryCreation;
