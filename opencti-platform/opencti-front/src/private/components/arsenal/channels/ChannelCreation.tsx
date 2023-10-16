import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
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
import { Theme } from '../../../../components/Theme';
import CustomFileUploader from '../../common/files/CustomFileUploader';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

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
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  confidence: number | undefined;
  file: File | undefined;
}

interface ChannelFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const ChannelCreationForm: FunctionComponent<ChannelFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    channel_types: Yup.array().nullable(),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
  };
  const channelValidator = useSchemaCreationValidation(
    CHANNEL_TYPE,
    basicShape,
  );
  const [commit] = useMutation<ChannelCreationMutation>(channelMutation);
  const onSubmit: FormikConfig<ChannelAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: ChannelCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      channel_types: values.channel_types,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'channelAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };
  const initialValues = useDefaultValues(CHANNEL_TYPE, {
    name: inputValue ?? '',
    channel_types: [],
    description: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    confidence: defaultConfidence,
    file: undefined,
  });
  return (
    <Formik
      initialValues={initialValues}
      validationSchema={channelValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Channel', 'Malware']}
          />
          <OpenVocabField
            type="channel_types_ov"
            name="channel_types"
            label={t('Channel type')}
            multiple
            containerStyle={fieldSpacingContainerStyle}
            onChange={setFieldValue}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
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
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const ChannelCreation = ({
  paginationOptions,
}: {
  paginationOptions: ChannelsLinesPaginationQuery$variables;
}) => {
  const { t } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_channels', paginationOptions, 'channelAdd');
  return (
    <Drawer
      title={t('Create a channel')}
      variant={DrawerVariant.create}
    >
      {({ onClose }) => (
        <ChannelCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default ChannelCreation;
