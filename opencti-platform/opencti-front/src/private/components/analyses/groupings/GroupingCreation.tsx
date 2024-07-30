import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import useHelper from 'src/utils/hooks/useHelper';
import { GroupingsLinesPaginationQuery$variables } from '@components/analyses/__generated__/GroupingsLinesPaginationQuery.graphql';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { Option } from '../../common/form/ReferenceField';
import { GroupingCreationMutation, GroupingCreationMutation$variables } from './__generated__/GroupingCreationMutation.graphql';
import type { Theme } from '../../../../components/Theme';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/fields/RichTextField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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
}));

const groupingMutation = graphql`
  mutation GroupingCreationMutation($input: GroupingAddInput!) {
    groupingAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...GroupingsLine_node
    }
  }
`;

const GROUPING_TYPE = 'Grouping';

interface GroupingAddInput {
  name: string;
  confidence: number | undefined;
  context: string;
  description: string;
  content: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | undefined;
}

interface GroupingFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined
  ) => void;
  onClose?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const GroupingCreationForm: FunctionComponent<GroupingFormProps> = ({
  updater,
  onClose,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    confidence: Yup.number().nullable(),
    context: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
  };
  const groupingValidator = useSchemaCreationValidation(
    GROUPING_TYPE,
    basicShape,
  );
  const [commit] = useApiMutation<GroupingCreationMutation>(
    groupingMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Grouping')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<GroupingAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: GroupingCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      content: values.content,
      context: values.context,
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
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'groupingAdd', response.groupingAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
        if (mapAfter) {
          navigate(
            `/dashboard/analyses/groupings/${response.groupingAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues(GROUPING_TYPE, {
    name: '',
    confidence: defaultConfidence,
    context: '',
    description: '',
    content: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={groupingValidator}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            detectDuplicate={['Grouping']}
            fullWidth
            askAi
          />
          <ConfidenceField
            entityType="Grouping"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Context')}
            type="grouping-context-ov"
            name="context"
            multiple={false}
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
            askAi={true}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t_i18n('Content')}
            fullWidth={true}
            style={{
              ...fieldSpacingContainerStyle,
              minHeight: 200,
              height: 200,
            }}
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
            {values.content.length > 0 && (
              <Button
                variant="contained"
                color="success"
                onClick={() => {
                  setMapAfter(true);
                  submitForm();
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create and map')}
              </Button>
            )}
          </div>
        </Form>
      )}
    </Formik>
  );
};

const GroupingCreation = ({
  paginationOptions,
}: {
  paginationOptions: GroupingsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_groupings', paginationOptions, 'groupingAdd');
  const CreateGroupingControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Grouping' {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a grouping')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateGroupingControlledDial : undefined}
    >
      <GroupingCreationForm updater={updater} />
    </Drawer>
  );
};

export default GroupingCreation;
