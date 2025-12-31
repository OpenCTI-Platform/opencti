import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { PositionCreationMutation, PositionCreationMutation$variables } from './__generated__/PositionCreationMutation.graphql';
import { PositionsLinesPaginationQuery$variables } from './__generated__/PositionsLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

const positionMutation = graphql`
  mutation PositionCreationMutation($input: PositionAddInput!) {
    positionAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      confidence
      entity_type
      parent_types
      ...PositionLine_node
    }
  }
`;

const POSITION_TYPE = 'Position';

interface PositionAddInput {
  name: string;
  description: string;
  confidence: number | null;
  latitude: string;
  longitude: string;
  street_address: string;
  postal_code: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface PositionFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const PositionCreationForm: FunctionComponent<PositionFormProps> = ({
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

  const { mandatoryAttributes } = useIsMandatoryAttribute(POSITION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable()
      .min(-90, t_i18n('Latitude must be between -90 and 90 degrees'))
      .max(90, t_i18n('Latitude must be between -90 and 90 degrees')),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable()
      .min(-180, t_i18n('Longitude must be between -180 and 180 degrees'))
      .max(180, t_i18n('Longitude must be between -180 and 180 degrees')),
    street_address: Yup.string()
      .nullable()
      .max(1000, t_i18n('The value is too long')),
    postal_code: Yup.string().nullable().max(1000, t_i18n('The value is too long')),
  }, mandatoryAttributes);

  const positionValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape).test(
    'coordinates-required-together',
    t_i18n('Both latitude and longitude must be provided together'),
    function validateCoordinates(values) {
      const { latitude, longitude } = values;
      const hasLatitude = latitude !== null && latitude !== undefined && latitude !== '';
      const hasLongitude = longitude !== null && longitude !== undefined && longitude !== '';

      if (hasLatitude && !hasLongitude) {
        return this.createError({
          path: 'longitude',
          message: t_i18n('Longitude is required when latitude is provided'),
        });
      }

      if (hasLongitude && !hasLatitude) {
        return this.createError({
          path: 'latitude',
          message: t_i18n('Latitude is required when longitude is provided'),
        });
      }

      return true;
    },
  );

  const [commit] = useApiMutation<PositionCreationMutation>(
    positionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Position')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<PositionCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'positionAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<PositionAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: PositionCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        confidence: parseInt(String(values.confidence), 10),
        latitude: parseFloat(values.latitude),
        longitude: parseFloat(values.longitude),
        street_address: values.street_address,
        postal_code: values.postal_code,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
        externalReferences: values.externalReferences.map(({ value }) => value),
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

  const initialValues = useDefaultValues(POSITION_TYPE, {
    name: inputValue ?? '',
    description: '',
    confidence: null,
    latitude: '',
    longitude: '',
    street_address: '',
    postal_code: '',
    createdBy: defaultCreatedBy ?? null,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: null,
  });

  return (
    <Formik<PositionAddInput>
      initialValues={initialValues}
      validationSchema={positionValidator}
      validateOnChange={false}
      validateOnBlur={false}
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
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              detectDuplicate={['Position']}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={fieldSpacingContainerStyle}
            />
            <ConfidenceField
              entityType="Position"
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              name="latitude"
              label={t_i18n('Latitude')}
              required={(mandatoryAttributes.includes('latitude'))}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              name="longitude"
              label={t_i18n('Longitude')}
              required={(mandatoryAttributes.includes('longitude'))}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              name="street_address"
              label={t_i18n('Street address')}
              required={(mandatoryAttributes.includes('street_address'))}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              name="postal_code"
              required={(mandatoryAttributes.includes('postal_code'))}
              label={t_i18n('Postal code')}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectLabelField
              name="objectLabel"
              required={(mandatoryAttributes.includes('objectLabel'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              required={(mandatoryAttributes.includes('externalReferences'))}
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
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
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

const PositionCreation = ({
  paginationOptions,
}: {
  paginationOptions: PositionsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_positions', paginationOptions, 'positionAdd');

  const CreatePositionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Position" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a position')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreatePositionControlledDial}
    >
      {({ onClose }) => (
        <PositionCreationForm
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

export default PositionCreation;
