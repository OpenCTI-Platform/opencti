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
import MarkDownField from '../../../../components/MarkDownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

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
    $input: StixMetaRelationshipAddInput!
  ) {
    channelRelationAdd(id: $id, input: $input) {
      from {
        ...ChannelEditionOverview_channel
      }
    }
  }
`;

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
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    channel_types: Yup.array(),
    description: Yup.string().nullable(),
    confidence: Yup.number(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const channelValidator = useYupSchemaBuilder('Channel', basicShape);

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
    R.assoc('x_opencti_workflow_id', convertStatus(t, channel)),
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
      onSubmit={onSubmit}>
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
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
            label={t('Channel types')}
            variant="edit"
            multiple={true}
            containerStyle={fieldSpacingContainerStyle}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
          />
          <Field
            component={MarkDownField}
            name="description"
            label={t('Description')}
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
            name="confidence"
            onFocus={editor.changeFocus}
            onChange={handleSubmitField}
            label={t('Confidence')}
            fullWidth={true}
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
            style={{ marginTop: 20, width: '100%' }}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: 20, width: '100%' }}
            helpertext={
              <SubscriptionFocus
                context={context}
                fieldname="objectMarking"
              />
            }
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
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
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
