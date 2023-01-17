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
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import { vocabulariesQuery } from '../../settings/attributes/VocabulariesLines';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';

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

const channelValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  channel_types: Yup.array().required(t('This field is required')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  confidence: Yup.number(),
});

const ChannelEditionOverviewComponent = (props) => {
  const { channel, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: channelEditionOverviewFocus,
    variables: {
      id: channel.id,
      input: {
        focusOn: name,
      },
    },
  });

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
    commitMutation({
      mutation: channelMutationFieldPatch,
      variables: {
        id: channel.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
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
      channelValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: channelMutationFieldPatch,
            variables: {
              id: channel.id,
              input: { key: name, value: finalValue },
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: channelMutationFieldPatch,
        variables: {
          id: channel.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(channel);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: channelMutationRelationAdd,
          variables: {
            id: channel.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: channelMutationRelationDelete,
          variables: {
            id: channel.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(channel);
  const objectMarking = convertMarkings(channel);
  const status = convertStatus(t, channel);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc(
      'channel_types',
      (channel.channel_types || []),
    ),
    R.pick([
      'name',
      'channel_types',
      'description',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
      'confidence',
    ]),
  )(channel);
  return (
    <QueryRenderer
      query={vocabulariesQuery}
      variables={{ category: 'channel_types_ov' }}
      render={({ props: rendererProps }) => {
        if (rendererProps && rendererProps.vocabularies) {
          return (
            <Formik
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={channelValidation(t)}
              onSubmit={onSubmit}
            >
              {({
                submitForm,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    onFocus={handleChangeFocus}
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
                    onFocus={handleChangeFocus}
                    onSubmit={handleSubmitField}
                    helperText={
                      <SubscriptionFocus
                        context={context}
                        fieldName="description"
                      />
                    }
                  />
                  <ConfidenceField
                    onFocus={handleChangeFocus}
                    onSubmit={handleSubmitField}
                    containerStyle={fieldSpacingContainerStyle}
                    editContext={context}
                    variant="edit"
                    entityType="Channel"
                  />
                  {channel.workflowEnabled && (
                    <StatusField
                      name="x_opencti_workflow_id"
                      type="Channel"
                      onFocus={handleChangeFocus}
                      onChange={handleSubmitField}
                      setFieldValue={setFieldValue}
                      style={{ marginTop: 20 }}
                      helpertext={
                        <SubscriptionFocus
                          context={context}
                          fieldName="x_opencti_workflow_id"
                        />
                      }
                    />
                  )}
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    helpertext={
                      <SubscriptionFocus
                        context={context}
                        fieldName="createdBy"
                      />
                    }
                    onChange={handleChangeCreatedBy}
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
                    onChange={handleChangeObjectMarking}
                  />
                  {enableReferences && (
                    <CommitMessage
                      submitForm={submitForm}
                      disabled={isSubmitting}
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
        }
        return <Loader variant="inElement" />;
      }}
    />
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
