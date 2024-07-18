import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/store';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import { ChannelCreationMutation, ChannelCreationMutation$variables } from './__generated__/ChannelCreationMutation.graphql';
import { ChannelsLinesPaginationQuery$variables } from './__generated__/ChannelsLinesPaginationQuery.graphql';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import useHelper from '../../../../utils/hooks/useHelper';
import TextField from '../../../../components/TextField';
import { splitMultilines } from '../../../../utils/String';
import ProgressBar from '../../../../components/ProgressBar';

const channelMutation = graphql`
  mutation ChannelCreationMutation($input: ChannelAddInput!) {
    channelAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...ChannelLine_node
    }
  }
`;

const CHANNEL_TYPE = 'Channel';

interface ChannelAddInput {
  name: string;
  channel_types: string[];
  description: string;
  createdBy: Option | null;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  confidence: number | null;
  file: File | null;
}

interface ChannelFormProps {
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

export const ChannelCreationForm: FunctionComponent<ChannelFormProps> = ({
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
    channel_types: Yup.array().nullable(),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
  };
  const channelValidator = useSchemaCreationValidation(
    CHANNEL_TYPE,
    basicShape,
  );

  const [commit] = useApiMutation<ChannelCreationMutation>(channelMutation);
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
  } = useBulkCommit<ChannelCreationMutation$variables['input'], ChannelCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'channelAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<ChannelAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const inputs: ChannelCreationMutation$variables['input'][] = allNames.map((name) => ({
      name,
      description: values.description,
      channel_types: values.channel_types,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    }));

    bulkCommit({
      inputs,
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

  const initialValues = useDefaultValues(CHANNEL_TYPE, {
    name: inputValue ?? '',
    channel_types: [],
    description: '',
    createdBy: defaultCreatedBy ?? null,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    confidence: defaultConfidence ?? null,
    file: null,
  });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={channelValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, resetForm, validateField }) => (
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
                  onCompleted?.();
                }}
              >
                <BulkResult inputToString={(input) => input.name} />
              </ProgressBar>
            </>
          )}
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={isFeatureEnable('BULK_ENTITIES') ? BulkTextField : TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              detectDuplicate={['Channel', 'Malware']}
            />
            <OpenVocabField
              type="channel_types_ov"
              name="channel_types"
              label={t_i18n('Channel type')}
              multiple
              containerStyle={fieldSpacingContainerStyle}
              onChange={setFieldValue}
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
              entityType="Channel"
              containerStyle={fieldSpacingContainerStyle}
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

const ChannelCreation = ({
  paginationOptions,
}: {
  paginationOptions: ChannelsLinesPaginationQuery$variables;
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_channels', paginationOptions, 'channelAdd');
  const [bulkOpen, setBulkOpen] = useState(false);

  return (
    <Drawer
      title={t_i18n('Create a channel')}
      variant={DrawerVariant.create}
      header={isFeatureEnable('BULK_ENTITIES')
        ? <BulkTextModalButton onClick={() => setBulkOpen(true)} />
        : <></>
      }
    >
      {({ onClose }) => (
        <ChannelCreationForm
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

export default ChannelCreation;
