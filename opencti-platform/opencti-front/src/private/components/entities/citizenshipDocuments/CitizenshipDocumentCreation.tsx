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
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import { TextField as MuiTextField, MenuItem } from '@mui/material';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import OpenVocabField from '../../common/form/OpenVocabField';
import { CitizenshipDocumentCreationMutation, CitizenshipDocumentCreationMutation$variables } from './__generated__/CitizenshipDocumentCreationMutation.graphql';
import { CitizenshipDocumentsLinesPaginationQuery$variables } from './__generated__/CitizenshipDocumentsLinesPaginationQuery.graphql';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
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
import FormButtonContainer from '@common/form/FormButtonContainer';
import useMarkdownCreationFilesInput from '../../../../utils/markdown/useMarkdownCreationFilesInput';

const citizenshipDocumentMutation = graphql`
  mutation CitizenshipDocumentCreationMutation($input: CitizenshipDocumentAddInput!) {
    citizenshipDocumentAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      confidence
      description
      entity_type
      parent_types
      ...CitizenshipDocumentLine_node
    }
  }
`;

const CITIZENSHIP_DOCUMENT_TYPE = 'Citizenship-Document';

interface CitizenshipDocumentAddInput {
  name: string;
  description: string;
  confidence: number | null;
  x_opencti_reliability: string | undefined;
  x_opencti_citizenship_document_id: string | undefined;
  x_opencti_citizenship_document_type: string | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface CitizenshipDocumentFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const CitizenshipDocumentCreationForm: FunctionComponent<CitizenshipDocumentFormProps> = ({
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

  const { mandatoryAttributes } = useIsMandatoryAttribute(CITIZENSHIP_DOCUMENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().min(1),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number().nullable(),
    x_opencti_reliability: Yup.string()
      .nullable(),
    x_opencti_citizenship_document_id: Yup.string().nullable(),
    x_opencti_citizenship_document_type: Yup.string().nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const citizenshipDocumentValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<CitizenshipDocumentCreationMutation>(
    citizenshipDocumentMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Citizenship-Document')} ${t_i18n('successfully created')}` },
  );
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<CitizenshipDocumentCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'citizenshipDocumentAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<CitizenshipDocumentAddInput>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const allNames = splitMultilines(values.name);
    const variables: CitizenshipDocumentCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        ...buildCreationFilesInput(values.file ? [values.file] : []),
        name,
        description: values.description,
        x_opencti_reliability: values.x_opencti_reliability,
        x_opencti_citizenship_document_id: values.x_opencti_citizenship_document_id,
        x_opencti_citizenship_document_type: values.x_opencti_citizenship_document_type,
        createdBy: values.createdBy?.value,
        confidence: parseInt(String(values.confidence), 10),
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
        externalReferences: values.externalReferences.map(({ value }) => value),
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
    CITIZENSHIP_DOCUMENT_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      x_opencti_reliability: undefined,
      x_opencti_citizenship_document_id: '',
      x_opencti_citizenship_document_type: 'citizenship document',
      confidence: null,
      createdBy: defaultCreatedBy ?? undefined, // undefined for Require Fields Flagging, if Configured Mandatory Field
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: null,
    },
  );

  return (
    <Formik<CitizenshipDocumentAddInput>
      initialValues={initialValues}
      validationSchema={citizenshipDocumentValidator}
      validateOnChange={false}
      validateOnBlur={false}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({
        submitForm,
        handleReset,
        isSubmitting,
        setFieldValue,
        values,
        resetForm,
      }) => (
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
              detectDuplicate={['User']}
            />

            <Field name="x_opencti_document_type">
              {({ field }) => (
                <MuiTextField
                  {...field}
                  select
                  fullWidth={true}
                  label={t_i18n('Document type')}
                  style={{ marginTop: 20, width: '100%' }}
                >
                  <MenuItem value="citizenship document">{t_i18n('Citizenship Document')}</MenuItem>
                  <MenuItem value="national id">{t_i18n('National ID')}</MenuItem>
                  <MenuItem value="passport">{t_i18n('Passport')}</MenuItem>
                </MuiTextField>
              )}
            </Field>
            <Field
              component={BulkTextField}
              variant="standard"
              name="x_opencti_citizenship_document_id"
              label={t_i18n('Document ID')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              multiline={true}
              rows="4"
              style={fieldSpacingContainerStyle}
              autoPersistOnBlur={false}
              registerMarkdownImagesController={registerMarkdownImagesController}
              uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
            />
            <ConfidenceField
              entityType="CitizenshipDocument"
              containerStyle={fieldSpacingContainerStyle}
            />
            <OpenVocabField
              label={t_i18n('Reliability')}
              type="reliability_ov"
              name="x_opencti_reliability"
              required={(mandatoryAttributes.includes('x_opencti_reliability'))}
              containerStyle={fieldSpacingContainerStyle}
              multiple={false}
              onChange={setFieldValue}
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
            <FormButtonContainer>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        </>
      )}
    </Formik>
  );
};

const CitizenshipDocumentCreation = ({ paginationOptions }: {
  paginationOptions: CitizenshipDocumentsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_citizenship_documents',
    paginationOptions,
    'citizenshipDocumentAdd',
  );
  const CreateCitizenshipDocumentControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Citizenship-Document" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a citizenship document')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateCitizenshipDocumentControlledDial}
    >
      {({ onClose }) => (
        <CitizenshipDocumentCreationForm
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

export default CitizenshipDocumentCreation;
