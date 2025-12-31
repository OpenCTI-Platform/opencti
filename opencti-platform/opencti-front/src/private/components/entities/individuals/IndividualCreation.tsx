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
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import OpenVocabField from '../../common/form/OpenVocabField';
import { IndividualCreationMutation, IndividualCreationMutation$variables } from './__generated__/IndividualCreationMutation.graphql';
import { IndividualsLinesPaginationQuery$variables } from './__generated__/IndividualsLinesPaginationQuery.graphql';
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

const individualMutation = graphql`
  mutation IndividualCreationMutation($input: IndividualAddInput!) {
    individualAdd(input: $input) {
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
      ...IndividualLine_node
    }
  }
`;

const INDIVIDUAL_TYPE = 'Individual';

interface IndividualAddInput {
  name: string;
  description: string;
  confidence: number | null;
  x_opencti_reliability: string | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface IndividualFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const IndividualCreationForm: FunctionComponent<IndividualFormProps> = ({
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

  const { mandatoryAttributes } = useIsMandatoryAttribute(INDIVIDUAL_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().min(2),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number().nullable(),
    x_opencti_reliability: Yup.string()
      .nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const individualValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<IndividualCreationMutation>(
    individualMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Individual')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<IndividualCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'individualAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<IndividualAddInput>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const allNames = splitMultilines(values.name);
    const variables: IndividualCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        x_opencti_reliability: values.x_opencti_reliability,
        createdBy: values.createdBy?.value,
        confidence: parseInt(String(values.confidence), 10),
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
    INDIVIDUAL_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      x_opencti_reliability: undefined,
      confidence: null,
      createdBy: defaultCreatedBy ?? undefined, // undefined for Require Fields Flagging, if Configured Mandatory Field
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: null,
    },
  );

  return (
    <Formik<IndividualAddInput>
      initialValues={initialValues}
      validationSchema={individualValidator}
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
            <ConfidenceField
              entityType="Individual"
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

const IndividualCreation = ({ paginationOptions }: {
  paginationOptions: IndividualsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_individuals',
    paginationOptions,
    'individualAdd',
  );
  const CreateIndividualControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Individual" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a individual')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateIndividualControlledDial}
    >
      {({ onClose }) => (
        <IndividualCreationForm
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

export default IndividualCreation;
