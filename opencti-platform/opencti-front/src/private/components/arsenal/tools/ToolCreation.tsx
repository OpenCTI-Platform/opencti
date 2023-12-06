import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { ToolsLinesPaginationQuery$variables } from './__generated__/ToolsLinesPaginationQuery.graphql';
import type { Theme } from '../../../../components/Theme';
import { ToolCreationMutation, ToolCreationMutation$variables } from './__generated__/ToolCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  createBtn: {
    marginLeft: '10px',
    padding: '7px 10px',
  },
}));

const toolMutation = graphql`
  mutation ToolCreationMutation($input: ToolAddInput!) {
    toolAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...ToolLine_node
    }
  }
`;

const TOOL_TYPE = 'Tool';

interface ToolAddInput {
  name: string
  description: string
  createdBy: Option | undefined
  objectMarking: Option[]
  killChainPhases: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  tool_types: string[]
  confidence: number | undefined
  file: File | undefined
}

interface ToolFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const ToolCreationForm: FunctionComponent<ToolFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    tool_types: Yup.array().nullable(),
  };
  const toolValidator = useSchemaCreationValidation(TOOL_TYPE, basicShape);

  const [commit] = useMutation<ToolCreationMutation>(toolMutation);

  const onSubmit: FormikConfig<ToolAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: ToolCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
      objectLabel: values.objectLabel.map((v) => v.value),
      tool_types: values.tool_types,
      confidence: parseInt(String(values.confidence), 10),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'toolAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        MESSAGING$.notifyError(`${error}`);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_Tool')} ${t_i18n('successfully created')}`);
      },
    });
  };

  const initialValues = useDefaultValues(
    TOOL_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      killChainPhases: [],
      objectLabel: [],
      externalReferences: [],
      tool_types: [],
      confidence: defaultConfidence,
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={toolValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
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
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const ToolCreation = ({
  paginationOptions,
}: {
  paginationOptions: ToolsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_tools', paginationOptions, 'toolAdd');

  return (
    <Drawer
      title={t_i18n('Create a tool')}
      controlledDial={({ onOpen }) => (
        <Button
          className={classes.createBtn}
          color='primary'
          size='small'
          variant='contained'
          onClick={onOpen}
        >
          {t_i18n('Create')} {t_i18n('entity_Tool')} <Add />
        </Button>
      )}
    >
      {({ onClose }) => (
        <ToolCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default ToolCreation;
