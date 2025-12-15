import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { InfrastructureCreationMutation, InfrastructureCreationMutation$variables } from './__generated__/InfrastructureCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import { InfrastructuresLinesPaginationQuery$variables } from '../__generated__/InfrastructuresLinesPaginationQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const infrastructureMutation = graphql`
  mutation InfrastructureCreationMutation($input: InfrastructureAddInput!) {
    infrastructureAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...InfrastructuresLine_node
    }
  }
`;

const INFRASTRUCTURE_TYPE = 'Infrastructure';

interface InfrastructureAddInput {
  name: string;
  infrastructure_types: string[];
  confidence: number | null;
  description: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  first_seen: Date | null;
  last_seen: Date | null;
  killChainPhases: FieldOption[];
  file: File | null;
}

interface InfrastructureFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const InfrastructureCreationForm: FunctionComponent<InfrastructureFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  bulkModalOpen = false,
  onBulkModalClose,
  inputValue,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(INFRASTRUCTURE_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    infrastructure_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .min(
        Yup.ref('first_seen'),
        'The last seen date can\'t be before first seen date',
      )
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  }, mandatoryAttributes);
  const infrastructureValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );

  const [commit] = useApiMutation<InfrastructureCreationMutation>(
    infrastructureMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Infrastructure')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<InfrastructureCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'infrastructureAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<InfrastructureAddInput>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const allNames = splitMultilines(values.name);
    const variables: InfrastructureCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        infrastructure_types: values.infrastructure_types,
        confidence: parseInt(String(values.confidence), 10),
        first_seen: values.first_seen ? parse(values.first_seen).format() : null,
        last_seen: values.last_seen ? parse(values.last_seen).format() : null,
        killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
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

  const initialValues = useDefaultValues(
    INFRASTRUCTURE_TYPE,
    {
      name: inputValue ?? '',
      infrastructure_types: [],
      confidence: defaultConfidence ?? null,
      description: '',
      createdBy: defaultCreatedBy ?? null,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      first_seen: null,
      last_seen: null,
      killChainPhases: [],
      file: null,
    },
  );

  return (
    <Formik<InfrastructureAddInput>
      initialValues={initialValues}
      validationSchema={infrastructureValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
              detectDuplicate={['Infrastructure']}
            />
            <OpenVocabField
              label={t_i18n('Infrastructure types')}
              type="infrastructure-type-ov"
              name="infrastructure_types"
              required={(mandatoryAttributes.includes('infrastructure_types'))}
              containerStyle={fieldSpacingContainerStyle}
              multiple={true}
              onChange={(name, value) => setFieldValue(name, value)}
            />
            <ConfidenceField
              entityType="Infrastructure"
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={DateTimePickerField}
              name="first_seen"
              textFieldProps={{
                label: t_i18n('First seen'),
                required: (mandatoryAttributes.includes('first_seen')),
                variant: 'standard',
                fullWidth: true,
                style: { ...fieldSpacingContainerStyle },
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_seen"
              textFieldProps={{
                label: t_i18n('Last seen'),
                required: (mandatoryAttributes.includes('last_seen')),
                variant: 'standard',
                fullWidth: true,
                style: { ...fieldSpacingContainerStyle },
              }}
            />
            <KillChainPhasesField
              name="killChainPhases"
              required={(mandatoryAttributes.includes('killChainPhases'))}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows="4"
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

const InfrastructureCreation = ({ paginationOptions }: {
  paginationOptions: InfrastructuresLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_infrastructures',
    paginationOptions,
    'infrastructureAdd',
  );

  const CreateInfrastructureControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Infrastructure" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create an infrastructure')}
      controlledDial={CreateInfrastructureControlledDial}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
    >
      {({ onClose }) => (
        <InfrastructureCreationForm
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

export default InfrastructureCreation;
