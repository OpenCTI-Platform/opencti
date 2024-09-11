import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { Option } from '../../common/form/ReferenceField';
import { ThreatActorsGroupCardsPaginationQuery$variables } from './__generated__/ThreatActorsGroupCardsPaginationQuery.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { ThreatActorGroupCreationMutation, ThreatActorGroupCreationMutation$variables } from './__generated__/ThreatActorGroupCreationMutation.graphql';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import { splitMultilines } from '../../../../utils/String';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const ThreatActorGroupMutation = graphql`
  mutation ThreatActorGroupCreationMutation($input: ThreatActorGroupAddInput!) {
    threatActorGroupAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...ThreatActorGroupCard_node
    }
  }
`;

interface ThreatActorGroupAddInput {
  name: string;
  threat_actor_types: string[];
  confidence: number | null;
  description: string;
  createdBy: Option | null;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface ThreatActorGroupFormProps {
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

export const ThreatActorGroupCreationForm: FunctionComponent<
ThreatActorGroupFormProps
> = ({
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

  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
  };
  const threatActorGroupValidator = useSchemaCreationValidation(
    'Threat-Actor-Group',
    basicShape,
  );

  const [commit] = useApiMutation<ThreatActorGroupCreationMutation>(
    ThreatActorGroupMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Threat-Actor-Group')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<ThreatActorGroupCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'threatActorGroupAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<ThreatActorGroupAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: ThreatActorGroupCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        threat_actor_types: values.threat_actor_types,
        confidence: parseInt(String(values.confidence), 10),
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

  const initialValues = useDefaultValues('Threat-Actor-Group', {
    name: inputValue ?? '',
    threat_actor_types: [],
    confidence: defaultConfidence ?? null,
    description: '',
    createdBy: defaultCreatedBy ?? null,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: null,
  });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={threatActorGroupValidator}
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
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={BulkTextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              askAi={true}
              detectDuplicate={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Malware',
              ]}
            />
            <OpenVocabField
              type="threat-actor-group-type-ov"
              name="threat_actor_types"
              label={t_i18n('Threat actor types')}
              multiple={true}
              containerStyle={{ width: '100%', marginTop: 20 }}
              onChange={setFieldValue}
            />
            <ConfidenceField
              entityType="Threat-Actor-Group"
              containerStyle={{ width: '100%', marginTop: 20 }}
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

const ThreatActorGroupCreation = ({
  paginationOptions,
}: {
  paginationOptions: ThreatActorsGroupCardsPaginationQuery$variables;
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_threatActorsGroup',
    paginationOptions,
    'threatActorGroupAdd',
  );

  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const CreateThreatActorGroupControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Threat-Actor-Group' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a threat actor group')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateThreatActorGroupControlledDial : undefined}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
    >
      {({ onClose }) => (
        <ThreatActorGroupCreationForm
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

export default ThreatActorGroupCreation;
