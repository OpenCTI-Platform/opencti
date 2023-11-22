import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const channelMutationFieldPatch = graphql`
  mutation ChannelEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    channelFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...ChannelEditionOverview_channel
      ...Channel_channel
    }
  }
`;

export const channelEditionOverviewFocus = graphql`
  mutation ChannelEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    channelContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const channelMutationRelationAdd = graphql`
  mutation ChannelEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    channelRelationAdd(id: $id, input: $input) {
      from {
        ...ChannelEditionOverview_channel
      }
    }
  }
`;
const CHANNEL_TYPE = 'Channel';

const channelMutationRelationDelete = graphql`
  mutation ChannelEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    channelRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...ChannelEditionOverview_channel
    }
  }
`;

const ChannelEditionOverviewComponent = (props) => {
  const { channel, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    CHANNEL_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    channel_types: Yup.array().nullable(),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const channelValidator = useSchemaEditionValidation(CHANNEL_TYPE, basicShape);

  const queries = {
    fieldPatch: channelMutationFieldPatch,
    relationAdd: channelMutationRelationAdd,
    relationDelete: channelMutationRelationDelete,
    editionFocus: channelEditionOverviewFocus,
  };
  const editor = useFormEditor(channel, enableReferences, queries, channelValidator);

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('channel_types', values.channel_types),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: channel.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      channelValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: channel.id,
              input: { key: name, value: finalValue },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(channel)),
    R.assoc('objectMarking', convertMarkings(channel)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, channel)),
    R.assoc('channel_types', (channel.channel_types || [])),
    R.assoc('references', []),
    R.pick([
      'name',
      'channel_types',
      'references',
      'description',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
      'confidence',
    ]),
  )(channel);
  return (
    <Formik enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={channelValidator}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={channel} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            type="channel_types_ov"
            name="channel_types"
            label={t_i18n('Channel types')}
            required={(mandatoryAttributes.includes('channel_types'))}
            variant="edit"
            multiple={true}
            containerStyle={fieldSpacingContainerStyle}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Channel"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          {channel.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Channel"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={
                <SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />
              }
            />
          )}
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking"/>
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={channel.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(ChannelEditionOverviewComponent, {
  channel: graphql`
    fragment ChannelEditionOverview_channel on Channel {
      id
      name
      channel_types
      description
      confidence
      entity_type
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
    }
  `,
});
