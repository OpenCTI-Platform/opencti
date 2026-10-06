import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { citizenshipDocumentCreationMutation } from '@components/entities/citizenshipDocuments/CitizenshipDocumentCreation';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import {
  CitizenshipDocumentCreationMutation,
  CitizenshipDocumentCreationMutation$variables,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentCreationMutation.graphql';
import { FormikConfig } from 'formik/dist/types';
import OpenVocabField from '@components/common/form/OpenVocabField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectLabelField from '@components/common/form/ObjectLabelField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { getCitizenshipDocumentValidator, CITIZENSHIP_DOCUMENT_ENTITY_TYPE } from '@components/entities/citizenshipDocuments/CitizenshipDocumentUtils';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import { handleErrorInForm } from '../../../../relay/environment';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import { useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import FormButtonContainer from '@common/form/FormButtonContainer';
import useMarkdownCreationFilesInput from '../../../../utils/markdown/useMarkdownCreationFilesInput';

interface CitizenshipDocumentCreationFormData {
  name: string;
  description: string;
  x_opencti_citizenship_document_type: string | undefined;
  createdBy: FieldOption | undefined;
  objectLabel: FieldOption[];
  objectMarking: FieldOption[];
}

interface CitizenshipDocumentCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const CitizenshipDocumentCreationForm: FunctionComponent<CitizenshipDocumentCreationFormProps> = ({
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(CITIZENSHIP_DOCUMENT_ENTITY_TYPE);
  const citizenshipDocumentValidator = getCitizenshipDocumentValidator(mandatoryAttributes);

  const [commit] = useApiMutation<CitizenshipDocumentCreationMutation>(
    citizenshipDocumentCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_CitizenshipDocument')} ${t_i18n('successfully created')}` },
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

  const onSubmit: FormikConfig<CitizenshipDocumentCreationFormData>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const allNames = splitMultilines(values.name);
    const variables: CitizenshipDocumentCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        ...buildCreationFilesInput(),
        name,
        description: values.description,
        x_opencti_citizenship_document_type: values.x_opencti_citizenship_document_type,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
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
    CITIZENSHIP_DOCUMENT_ENTITY_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      x_opencti_citizenship_document_type: undefined,
      createdBy: defaultCreatedBy ?? undefined, // undefined for Require Fields Flagging, if Configured Mandatory Field
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
    },
  );

  return (
    <Formik<CitizenshipDocumentCreationFormData>
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
              variant="outlined"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              detectDuplicate={['citizenshipDocument']}
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
              autoPersistOnBlur={false}
              registerMarkdownImagesController={registerMarkdownImagesController}
              uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
            />
            { /* TODO Improve customization (vocab with letter range) 2662 */}
            <OpenVocabField
              label={t_i18n('Citizenship document type')}
              type="citizenship_document_type_ov"
              name="x_opencti_citizenship_document_type"
              required={(mandatoryAttributes.includes('x_opencti_citizenship_document_type'))}
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

export default CitizenshipDocumentCreationForm;
