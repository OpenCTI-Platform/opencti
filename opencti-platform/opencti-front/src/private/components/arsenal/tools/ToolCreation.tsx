import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { ToolsLinesPaginationQuery$variables } from '@components/arsenal/__generated__/ToolsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { ToolCreationMutation, ToolCreationMutation$variables } from './__generated__/ToolCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useHelper from '../../../../utils/hooks/useHelper';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

const toolMutation = graphql`
  mutation ToolCreationMutation($input: ToolAddInput!) {
    toolAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...ToolsLine_node
    }
  }
`;

const TOOL_TYPE = 'Tool';

interface ToolAddInput {
  name: string
  description: string
  createdBy: Option | null
  objectMarking: Option[]
  killChainPhases: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  tool_types: string[]
  confidence: number | null
  file: File | null
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
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    tool_types: Yup.array().nullable(),
  };
  const toolValidator = useSchemaCreationValidation(TOOL_TYPE, basicShape);

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
      confidence: defaultConfidence ?? null,
      file: null,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={toolValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, resetForm }) => (
        <>
          {isFeatureEnable('BULK_ENTITIES') && (
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
            </>
          )}
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={isFeatureEnable('BULK_ENTITIES') ? BulkTextField : TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              detectDuplicate={['Tool', 'Malware']}
              askAi={true}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              askAi={true}
            />
            <ConfidenceField
              entityType="Tool"
              containerStyle={fieldSpacingContainerStyle}
            />
            <KillChainPhasesField
              name="killChainPhases"
              style={fieldSpacingContainerStyle}
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
            <OpenVocabField
              type="tool_types_ov"
              name="tool_types"
              label={t_i18n('Tool types')}
              multiple={true}
              containerStyle={fieldSpacingContainerStyle}
              onChange={setFieldValue}
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

const CreateToolControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial entityType='Tool' {...props} />
);

const ToolCreation = ({
  paginationOptions,
}: {
  paginationOptions: ToolsLinesPaginationQuery$variables;
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tools', paginationOptions, 'toolAdd');

  return (
    <Drawer
      title={t_i18n('Create a tool')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      header={isFeatureEnable('BULK_ENTITIES')
        ? <BulkTextModalButton onClick={() => setBulkOpen(true)} />
        : <></>
      }
      controlledDial={isFABReplaced ? CreateToolControlledDial : undefined}
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
