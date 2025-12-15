import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import { AdministrativeAreasLinesPaginationQuery$variables } from './__generated__/AdministrativeAreasLinesPaginationQuery.graphql';
import { AdministrativeAreaCreationMutation, AdministrativeAreaCreationMutation$variables } from './__generated__/AdministrativeAreaCreationMutation.graphql';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import { handleErrorInForm } from '../../../../relay/environment';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

const administrativeAreaMutation = graphql`
  mutation AdministrativeAreaCreationMutation(
    $input: AdministrativeAreaAddInput!
  ) {
    administrativeAreaAdd(input: $input) {
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
      ...AdministrativeAreaLine_node
    }
  }
`;

interface AdministrativeAreaAddInput {
  name: string;
  description: string;
  latitude: string;
  longitude: string;
  confidence: number | null;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: FieldOption[];
  file: File | null;
}

interface AdministrativeAreaFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const ADMINISTRATIVE_AREA_TYPE = 'Administrative-Area';

export const AdministrativeAreaCreationForm: FunctionComponent<AdministrativeAreaFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(ADMINISTRATIVE_AREA_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
  }, mandatoryAttributes);
  const administrativeAreaValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<AdministrativeAreaCreationMutation>(
    administrativeAreaMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Administrative-Area')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<AdministrativeAreaCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'administrativeAreaAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<AdministrativeAreaAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: AdministrativeAreaCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        latitude: parseFloat(values.latitude),
        longitude: parseFloat(values.longitude),
        description: values.description,
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

  const initialValues = useDefaultValues<AdministrativeAreaAddInput>(
    ADMINISTRATIVE_AREA_TYPE,
    {
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
    },
  );

  return (
    <Formik<AdministrativeAreaAddInput>
      initialValues={initialValues}
      validationSchema={administrativeAreaValidator}
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
              detectDuplicate={['Administrative-Area']}
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
              entityType="Administrative-Area"
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
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              required={(mandatoryAttributes.includes('createdBy'))}
            />
            <ObjectLabelField
              name="objectLabel"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
              required={(mandatoryAttributes.includes('objectLabel'))}
            />
            <ObjectMarkingField
              name="objectMarking"
              setFieldValue={setFieldValue}
              style={fieldSpacingContainerStyle}
              required={(mandatoryAttributes.includes('objectMarking'))}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.externalReferences}
              required={(mandatoryAttributes.includes('externalReferences'))}
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

const AdministrativeAreaCreation = ({
  paginationOptions,
}: {
  paginationOptions: AdministrativeAreasLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(
      store,
      'Pagination_administrativeAreas',
      paginationOptions,
      'administrativeAreaAdd',
    );
  };

  const CreateAreaControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Administrative-Area" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create an area')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateAreaControlledDial}
    >
      {({ onClose }) => (
        <AdministrativeAreaCreationForm
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

export default AdministrativeAreaCreation;
