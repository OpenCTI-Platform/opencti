import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { SystemCreationMutation, SystemCreationMutation$variables } from './__generated__/SystemCreationMutation.graphql';
import { SystemsLinesPaginationQuery$variables } from './__generated__/SystemsLinesPaginationQuery.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
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

const systemMutation = graphql`
  mutation SystemCreationMutation($input: SystemAddInput!) {
    systemAdd(input: $input) {
      id
      standard_id
      name
      description
      confidence
      entity_type
      parent_types
      ...SystemLine_node
    }
  }
`;

const SYSTEM_TYPE = 'System';

interface SystemAddInput {
  name: string;
  description: string;
  confidence: number | null;
  x_opencti_reliability: string | undefined;
  createdBy: Option | null;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface SystemFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const SystemCreationForm: FunctionComponent<SystemFormProps> = ({
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

  const basicShape = {
    name: Yup.string()
      .min(2)
      .required(t_i18n('This field is required')),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100'))
      .nullable(),
    x_opencti_reliability: Yup.string()
      .nullable(),
  };
  const systemValidator = useSchemaCreationValidation(SYSTEM_TYPE, basicShape);

  const [commit] = useApiMutation<SystemCreationMutation>(
    systemMutation,
    undefined,
    { successMessage: `${t_i18n('entity_System')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<SystemCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'systemAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<SystemAddInput>['onSubmit'] = (
    values,
    {
      setSubmitting,
      setErrors,
      resetForm,
    },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: SystemCreationMutation$variables[] = allNames.map((name) => ({
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
    SYSTEM_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      confidence: null,
      x_opencti_reliability: undefined,
      createdBy: defaultCreatedBy ?? null,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      file: null,
    },
  );

  return (
    <Formik<SystemAddInput>
      initialValues={initialValues}
      validationSchema={systemValidator}
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
              fullWidth={true}
              detectDuplicate={['User']}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <ConfidenceField
              entityType="System"
              containerStyle={fieldSpacingContainerStyle}
            />
            <OpenVocabField
              label={t_i18n('Reliability')}
              type="reliability_ov"
              name="x_opencti_reliability"
              containerStyle={fieldSpacingContainerStyle}
              multiple={false}
              onChange={setFieldValue}
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

const SystemCreation = ({
  paginationOptions,
}: {
  paginationOptions: SystemsLinesPaginationQuery$variables;
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_systems', paginationOptions, 'systemAdd');
  const CreateSystemControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='System' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a system')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={isFABReplaced ? CreateSystemControlledDial : undefined}
    >
      {({ onClose }) => (
        <SystemCreationForm
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

export default SystemCreation;
