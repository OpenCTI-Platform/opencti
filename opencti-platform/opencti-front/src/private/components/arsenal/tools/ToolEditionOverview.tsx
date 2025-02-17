import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { GenericContext } from '@components/common/model/GenericContextModel';
import { useTheme } from '@mui/styles';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { Option } from '../../common/form/ReferenceField';
import { ToolEditionOverview_tool$key } from './__generated__/ToolEditionOverview_tool.graphql';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import ConfidenceField from '../../common/form/ConfidenceField';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useHelper from '../../../../utils/hooks/useHelper';
import ToolDeletion from './ToolDeletion';

export const toolMutationFieldPatch = graphql`
  mutation ToolEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    toolEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ToolEditionOverview_tool
      }
    }
  }
`;

export const toolEditionOverviewFocus = graphql`
  mutation ToolEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    toolEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const toolMutationRelationAdd = graphql`
  mutation ToolEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ToolEditionOverview_tool
        }
      }
    }
  }
`;

export const toolMutationRelationDelete = graphql`
  mutation ToolEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ToolEditionOverview_tool
      }
    }
  }
`;

const toolEditionOverviewFragment = graphql`
  fragment ToolEditionOverview_tool on Tool {
    id
    name
    description
    tool_types
    tool_version
    confidence
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    killChainPhases {
      id
      kill_chain_name
      phase_name
    }
    objectMarking {
      id
      definition
    }
    status {
      id
      template {
        name
      }
    }
    workflowEnabled
  }
`;

interface ToolEditionOverviewProps {
  toolRef: ToolEditionOverview_tool$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface ToolEditionFormValues {
  name?: string;
  description?: string;
  tool_version?: string;
  createdBy?: Option
  killChainPhases?: Option[];
  objectMarking?: Option[];
  x_opencti_workflow_id?: Option
  references: Option[];
  message?: string;
}

const ToolEditionOverview: FunctionComponent<ToolEditionOverviewProps> = ({
  toolRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const tool = useFragment(toolEditionOverviewFragment, toolRef);

  const toolValidator = useSchemaEditionValidation('Tool', {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    tool_types: Yup.array().nullable(),
    tool_version: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
    references: Yup.array().nullable(),
  });

  const queries = {
    fieldPatch: toolMutationFieldPatch,
    relationAdd: toolMutationRelationAdd,
    relationDelete: toolMutationRelationDelete,
    editionFocus: toolEditionOverviewFocus,
  };

  const editor = useFormEditor(
    tool as GenericData,
    enableReferences,
    queries,
    toolValidator,
  );

  const handleSubmitField = (name: string, value: string[] | string) => {
    if (!enableReferences) {
      toolValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: tool.id,
              input: [{ key: name, value }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const onSubmit: FormikConfig<ToolEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      killChainPhases: values.killChainPhases?.map(({ value }) => value),
      objectMarking: values.objectMarking?.map(({ value }) => value),
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
      variables: {
        id: tool.id,
        input: inputValues,
        commitMessage: commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const initialValues = {
    name: tool.name,
    description: tool.description ?? '',
    confidence: tool.confidence,
    tool_types: tool.tool_types ?? [],
    tool_version: tool.tool_version ?? '',
    createdBy: convertCreatedBy(tool) as Option,
    killChainPhases: convertKillChainPhases(tool),
    objectMarking: convertMarkings(tool),
    x_opencti_workflow_id: convertStatus(t_i18n, tool) as Option,
    references: [],
  };

  return (
    <Formik<ToolEditionFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={toolValidator}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, setFieldValue, values }) => (
        <Form style={{ marginTop: theme.spacing(2) }}>
          <AlertConfidenceForEntity entity={tool} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required
            fullWidth
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={<SubscriptionFocus context={context} fieldName="name" />}
          />
          <Field
            component={TextField}
            name="description"
            label={t_i18n('Description')}
            multiline
            fullWidth
            style={{ marginTop: theme.spacing(2) }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={<SubscriptionFocus context={context} fieldName="description" />}
          />
          <ConfidenceField
            entityType="Tool"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            containerStyle={{ marginTop: theme.spacing(2) }}
            editContext={context}
            variant="edit"
          />
          <KillChainPhasesField
            name="killChainPhases"
            setFieldValue={setFieldValue}
            style={{ marginTop: theme.spacing(2) }}
            helpertext={<SubscriptionFocus context={context} fieldName="killChainPhases" />}
            onChange={editor.changeKillChainPhases}
          />
          {tool.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Tool"
              onFocus={editor.changeFocus}
              onChange={editor.changeField}
              setFieldValue={setFieldValue}
              style={{ marginTop: theme.spacing(2) }}
              helpertext={<SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />}
            />
          )}
          <CreatedByField
            name="createdBy"
            style={{ marginTop: theme.spacing(2) }}
            setFieldValue={setFieldValue}
            helpertext={<SubscriptionFocus context={context} fieldName="createdBy" />}
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: theme.spacing(2) }}
            setFieldValue={setFieldValue}
            helpertext={<SubscriptionFocus context={context} fieldName="objectMarking" />}
            onChange={editor.changeMarking}
          />
          <OpenVocabField
            type="tool_types_ov"
            name="tool_types"
            label={t_i18n('Tool types')}
            onSubmit={(name, value) => handleSubmitField(name, value as string)}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            multiple
            variant="edit"
            editContext={context}
          />
          <Field
            component={TextField}
            name="tool_version"
            label={t_i18n('Tool Version')}
            fullWidth
            style={{ marginTop: theme.spacing(2) }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={<SubscriptionFocus context={context} fieldName="tool_version" />}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', flex: 1 }}>
            {isFABReplaced ? <ToolDeletion id={tool.id} /> : <div />}
          </div>
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting}
              setFieldValue={setFieldValue}
              values={values.references}
              id={tool.id}
              open={false}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default ToolEditionOverview;
