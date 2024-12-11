import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import { CitiesLinesPaginationQuery$variables } from './__generated__/CitiesLinesPaginationQuery.graphql';
import { CityCreationMutation, CityCreationMutation$variables } from './__generated__/CityCreationMutation.graphql';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { Option } from '../../common/form/ReferenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useHelper from '../../../../utils/hooks/useHelper';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import { handleErrorInForm } from '../../../../relay/environment';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

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
  confidence: number | null;
  createdBy: Option | null;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  file: File | null;
}

interface CityFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const CITY_TYPE = 'City';

export const CityCreationForm: FunctionComponent<CityFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  bulkModalOpen = false,
  onBulkModalClose,
  inputValue,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100'))
      .nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
  };
  const cityValidator = useSchemaCreationValidation(CITY_TYPE, basicShape);

  const [commit] = useApiMutation<CityCreationMutation>(
    cityMutation,
    undefined,
    { successMessage: `${t_i18n('entity_City')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<CityCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'cityAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<CityAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: CityCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        latitude: parseFloat(values.latitude),
        longitude: parseFloat(values.longitude),
        confidence: parseInt(String(values.confidence), 10),
        objectMarking: values.objectMarking.map(({ value }) => value),
        objectLabel: values.objectLabel.map(({ value }) => value),
        externalReferences: values.externalReferences.map(({ value }) => value),
        createdBy: values.createdBy?.value,
        file: values.file,
      },
    }));

    bulkCommit({
      variables,
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
      },
      onCompleted: (total: number) => {
        setSubmitting(false);
        if (total < 2) {
          resetForm();
          onCompleted?.();
        }
      },
    });
  };

  const initialValues = useDefaultValues(CITY_TYPE, {
    name: inputValue ?? '',
    description: '',
    latitude: '',
    longitude: '',
    confidence: null,
    createdBy: defaultCreatedBy ?? null,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: null,
  });

  return (
    <Formik<CityAddInput>
      initialValues={initialValues}
      validationSchema={cityValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, resetForm }) => (
        <>
          <BulkTextModal
            open={bulkModalOpen}
            onClose={onBulkModalClose}
            onValidate={async (val) => {
              await setFieldValue('name', val);
              if (splitMultilines(val).length > 1) {
                await setFieldValue('file', null);
              }
            }}
            formValue={values.name}
          />
          <ProgressBar
            open={progressBarOpen}
            value={(bulkCurrentCount / bulkCount) * 100}
            label={`${bulkCurrentCount}/${bulkCount}`}
            title={t_i18n('Create multiple entities')}
            onClose={() => {
              setProgressBarOpen(false);
              resetForm();
              resetBulk();
              onCompleted?.();
            }}
          >
            <BulkResult variablesToString={(v) => v.input.name} />
          </ProgressBar>
          <Form>
            <Field
              component={BulkTextField}
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
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.externalReferences}
            />
            <Field
              component={CustomFileUploader}
              name="file"
              setFieldValue={setFieldValue}
              disabled={splitMultilines(values.name).length > 1}
              noFileSelectedLabel={splitMultilines(values.name).length > 1
                ? t_i18n('File upload not allowed in bulk creation')
                : undefined
              }
            />
            <div style={{
              marginTop: '20px',
              textAlign: 'right',
            }}
            >
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        </>
      )}
    </Formik>
  );
};

const CityCreation = ({
  paginationOptions,
}: {
  paginationOptions: CitiesLinesPaginationQuery$variables;
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_cities', paginationOptions, 'cityAdd');

  const CreateCityControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='City' {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a city')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={isFABReplaced ? CreateCityControlledDial : undefined}
    >
      {({ onClose }) => (
        <CityCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
};

export default CityCreation;
