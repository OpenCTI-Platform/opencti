import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { Dialog, DialogContent } from '@mui/material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { DataComponentsLinesPaginationQuery$variables } from '@components/techniques/__generated__/DataComponentsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { DataComponentCreationMutation, DataComponentCreationMutation$variables } from './__generated__/DataComponentCreationMutation.graphql';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

const dataComponentMutation = graphql`
  mutation DataComponentCreationMutation($input: DataComponentAddInput!) {
    dataComponentAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...DataComponentsLine_node
    }
  }
`;

interface DataComponentAddInput {
  name: string;
  description: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: FieldOption[];
  confidence: number | null;
  file: File | null;
}

interface DataComponentFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  inputValue?: string;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const DATA_COMPONENT_TYPE = 'Data-Component';

export const DataComponentCreationForm: FunctionComponent<DataComponentFormProps> = ({
  updater,
  onReset,
  inputValue,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(DATA_COMPONENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number()
      .nullable(),
  }, mandatoryAttributes);
  const dataComponentValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );

  const [commit] = useApiMutation<DataComponentCreationMutation>(
    dataComponentMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Data-Component')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<DataComponentCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'dataComponentAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<DataComponentAddInput>['onSubmit'] = (
    values: DataComponentAddInput,
    {
      setSubmitting,
      setErrors,
      resetForm,
    }: FormikHelpers<DataComponentAddInput>,
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: DataComponentCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
        externalReferences: values.externalReferences.map((v) => v.value),
        confidence: parseInt(String(values.confidence), 10),
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

  const initialValues = useDefaultValues<DataComponentAddInput>(
    DATA_COMPONENT_TYPE,
    {
      name: inputValue || '',
      description: '',
      createdBy: defaultCreatedBy ?? null,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      confidence: defaultConfidence ?? null,
      file: null,
    },
  );

  return (
    <Formik<DataComponentAddInput>
      initialValues={initialValues}
      validationSchema={dataComponentValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              detectDuplicate={['Data-Component']}
            />
            <ConfidenceField
              entityType="Data-Component"
              containerStyle={fieldSpacingContainerStyle}
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
              style={fieldSpacingContainerStyle}
              required={(mandatoryAttributes.includes('createdBy'))}
              setFieldValue={setFieldValue}
            />
            <ObjectLabelField
              name="objectLabel"
              style={fieldSpacingContainerStyle}
              required={(mandatoryAttributes.includes('objectLabel'))}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              required={(mandatoryAttributes.includes('objectMarking'))}
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              required={(mandatoryAttributes.includes('externalReferences'))}
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

const DataComponentCreation: FunctionComponent<{
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: DataComponentsLinesPaginationQuery$variables;
}> = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_dataComponents',
    paginationOptions,
    'dataComponentAdd',
  );
  const CreateDataComponentControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Data-Component" {...props} />
  );
  const CreateDataComponentControlledDialContextual = CreateDataComponentControlledDial({
    onOpen: handleOpen,
    onClose: () => {},
  });
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create a data component')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateDataComponentControlledDial}
    >
      {({ onClose }) => (
        <DataComponentCreationForm
          inputValue={inputValue}
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
  const renderContextual = () => (
    <div style={{ display: display ? 'block' : 'none' }}>
      <div style={{ marginTop: '5px' }}>
        {CreateDataComponentControlledDialContextual}
      </div>
      <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
        <DialogTitle>
          {t_i18n('Create a data component')}
          <BulkTextModalButton onClick={() => setBulkOpen(true)} />
        </DialogTitle>
        <DialogContent>
          <DataComponentCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
            bulkModalOpen={bulkOpen}
            onBulkModalClose={() => setBulkOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default DataComponentCreation;
