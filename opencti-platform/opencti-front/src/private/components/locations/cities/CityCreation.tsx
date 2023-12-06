import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import CreateEntityControlledDial from '@components/common/menus/CreateEntityControlledDial';
import { MESSAGING$ } from 'src/relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import type { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import { CitiesLinesPaginationQuery$variables } from './__generated__/CitiesLinesPaginationQuery.graphql';
import { CityCreationMutation$variables } from './__generated__/CityCreationMutation.graphql';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { Option } from '../../common/form/ReferenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

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

const cityMutation = graphql`
  mutation CityCreationMutation($input: CityAddInput!) {
    cityAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      confidence
      parent_types
      ...CityLine_node
    }
  }
`;

interface CityAddInput {
  name: string;
  description: string;
  latitude: string;
  longitude: string;
  confidence: number | undefined;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  file: File | undefined;
}

interface CityFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
}

const CITY_TYPE = 'City';

export const CityCreationForm: FunctionComponent<CityFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
  };
  const cityValidator = useSchemaCreationValidation(CITY_TYPE, basicShape);
  const [commit] = useMutation(cityMutation);
  const onSubmit: FormikConfig<CityAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input: CityCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      latitude: parseFloat(values.latitude),
      longitude: parseFloat(values.longitude),
      confidence: parseInt(String(values.confidence), 10),
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
          updater(store, 'cityAdd');
        }
      },
      onError: (error: Error) => {
        MESSAGING$.notifyError(`${error}`);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_City')} ${t_i18n('successfully deleted')}`);
      },
    });
  };
  const initialValues = useDefaultValues(CITY_TYPE, {
    name: '',
    description: '',
    latitude: '',
    longitude: '',
    confidence: undefined,
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });
  return (
    <Formik<CityAddInput>
      initialValues={initialValues}
      validationSchema={cityValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['City']}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={{ marginTop: 20 }}
          />
          <ConfidenceField
            entityType="City"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            name="latitude"
            label={t_i18n('Latitude')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            name="longitude"
            label={t_i18n('Longitude')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
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
            style={fieldSpacingContainerStyle}
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
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const CityCreation = ({
  paginationOptions,
}: {
  paginationOptions: CitiesLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_cities', paginationOptions, 'cityAdd');
  return (
    <Drawer
      title={t_i18n('Create a city')}
      controlledDial={CreateEntityControlledDial('entity_City')}
    >
      {({ onClose }) => (
        <CityCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default CityCreation;
