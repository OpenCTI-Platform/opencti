import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { Dialog, DialogContent } from '@mui/material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { DataComponentsLinesPaginationQuery$variables } from '@components/techniques/__generated__/DataComponentsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { Option } from '../../common/form/ReferenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { DataComponentCreationMutation, DataComponentCreationMutation$variables } from './__generated__/DataComponentCreationMutation.graphql';
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

const dataComponentMutation = graphql`
  mutation DataComponentCreationMutation($input: DataComponentAddInput!) {
    dataComponentAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...DataComponentsLine_node
    }
  }
`;

interface DataComponentAddInput {
  name: string
  description: string
  createdBy: Option | null
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: Option[]
  confidence: number | null
  file: File | null
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
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const basicShape = {
    name: Yup.string()
      .min(2)
      .required(t_i18n('This field is required')),
    description: Yup.string()
      .nullable(),
    confidence: Yup.number()
      .nullable(),
  };
  const dataComponentValidator = useSchemaCreationValidation(
    DATA_COMPONENT_TYPE,
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
              name="name"
              label={t_i18n('Name')}
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
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <CreatedByField
              name="createdBy"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
            />
            <ObjectLabelField
              name="objectLabel"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={{
                marginTop: 20,
                width: '100%',
              }}
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

const DataComponentCreation: FunctionComponent<{
  contextual?: boolean,
  display?: boolean,
  inputValue?: string,
  paginationOptions: DataComponentsLinesPaginationQuery$variables
}> = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const isFABReplaced = isFeatureEnable('FAB_REPLACED');
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
    <CreateEntityControlledDial entityType='Data-Component' {...props} />
  );
  const CreateDataComponentControlledDialContextual = CreateDataComponentControlledDial({
    onOpen: handleOpen,
    onClose: () => {},
  });
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create a data component')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      header={isFeatureEnable('BULK_ENTITIES')
        ? <BulkTextModalButton onClick={() => setBulkOpen(true)} />
        : <></>
      }
      controlledDial={isFABReplaced ? CreateDataComponentControlledDial : undefined}
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
      {isFABReplaced
        ? (
          <div style={{ marginTop: '5px' }}>
            {CreateDataComponentControlledDialContextual}
          </div>
        ) : (
          <Fab
            onClick={handleOpen}
            color="secondary"
            aria-label="Add"
            style={{
              position: 'fixed',
              bottom: 30,
              right: 30,
              zIndex: 2000,
            }}
          >
            <Add />
          </Fab>
        )
      }
      <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
        <DialogTitle>
          {t_i18n('Create a data component')}
          {isFeatureEnable('BULK_ENTITIES')
            ? <BulkTextModalButton onClick={() => setBulkOpen(true)} />
            : <></>
          }
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
