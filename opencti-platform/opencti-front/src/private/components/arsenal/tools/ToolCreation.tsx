import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { ToolsLinesPaginationQuery$variables } from '@components/arsenal/__generated__/ToolsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { ToolCreationMutation, ToolCreationMutation$variables } from './__generated__/ToolCreationMutation.graphql';
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
import TextField from '../../../../components/TextField';

const toolMutation = graphql`
  mutation ToolCreationMutation($input: ToolAddInput!) {
    toolAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...ToolsLine_node
    }
  }
`;

const TOOL_TYPE = 'Tool';

interface ToolAddInput {
  name: string;
  description: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  killChainPhases: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  tool_types: string[];
  tool_version: string;
  confidence: number | null;
  file: File | null;
}

interface ToolFormProps {
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

export const ToolCreationForm: FunctionComponent<ToolFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(
    TOOL_TYPE,
  );
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    tool_types: Yup.array().nullable(),
    tool_version: Yup.string().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<ToolCreationMutation>(
    toolMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Tool')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<ToolCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'toolAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<ToolAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: ToolCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
        objectLabel: values.objectLabel.map((v) => v.value),
        tool_types: values.tool_types,
        tool_version: values.tool_version,
        confidence: parseInt(String(values.confidence), 10),
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
    TOOL_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      createdBy: defaultCreatedBy ?? null,
      objectMarking: defaultMarkingDefinitions ?? [],
      killChainPhases: [],
      objectLabel: [],
      externalReferences: [],
      tool_types: [],
      tool_version: '',
      confidence: defaultConfidence ?? null,
      file: null,
    },
  );

  return (
    <Formik<ToolAddInput>
      initialValues={initialValues}
      validationSchema={validator}
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
              detectDuplicate={['Tool', 'Malware']}
              askAi={true}
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
              askAi={true}
            />
            <ConfidenceField
              entityType="Tool"
              containerStyle={fieldSpacingContainerStyle}
            />
            <KillChainPhasesField
              name="killChainPhases"
              required={(mandatoryAttributes.includes('killChainPhases'))}
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
            <OpenVocabField
              type="tool_types_ov"
              name="tool_types"
              label={t_i18n('Tool types')}
              required={(mandatoryAttributes.includes('tool_types'))}
              multiple={true}
              containerStyle={fieldSpacingContainerStyle}
              onChange={setFieldValue}
            />
            <Field
              component={TextField}
              name="tool_version"
              label={t_i18n('Tool Version')}
              required={(mandatoryAttributes.includes('tool_version'))}
              fullWidth={true}
              style={{ marginTop: 20 }}
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

const CreateToolControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial entityType="Tool" {...props} />
);

const ToolCreation = ({
  paginationOptions,
}: {
  paginationOptions: ToolsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tools', paginationOptions, 'toolAdd');

  return (
    <Drawer
      title={t_i18n('Create a tool')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateToolControlledDial}
    >
      {({ onClose }) => (
        <ToolCreationForm
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

export default ToolCreation;
