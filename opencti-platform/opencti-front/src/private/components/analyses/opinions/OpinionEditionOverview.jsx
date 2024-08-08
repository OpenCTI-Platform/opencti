import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useDynamicSchemaEditionValidation, useDynamicMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

export const opinionMutationFieldPatch = graphql`
    mutation OpinionEditionOverviewFieldPatchMutation(
        $id: ID!
        $input: [EditInput]!
    ) {
        opinionEdit(id: $id) {
            fieldPatch(input: $input) {
                ...OpinionEditionOverview_opinion
                ...Opinion_opinion
            }
        }
    }
`;

export const opinionEditionOverviewFocus = graphql`
    mutation OpinionEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
        opinionEdit(id: $id) {
            contextPatch(input: $input) {
                id
            }
        }
    }
`;

const opinionMutationRelationAdd = graphql`
    mutation OpinionEditionOverviewRelationAddMutation(
        $id: ID!
        $input: StixRefRelationshipAddInput!
    ) {
        opinionEdit(id: $id) {
            relationAdd(input: $input) {
                from {
                    ...OpinionEditionOverview_opinion
                }
            }
        }
    }
`;

const opinionMutationRelationDelete = graphql`
    mutation OpinionEditionOverviewRelationDeleteMutation(
        $id: ID!
        $toId: StixRef!
        $relationship_type: String!
    ) {
        opinionEdit(id: $id) {
            relationDelete(toId: $toId, relationship_type: $relationship_type) {
                ...OpinionEditionOverview_opinion
            }
        }
    }
`;

const OPINION_TYPE = 'Opinion';

const OpinionEditionOverviewComponent = (props) => {
  const { opinion, context } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useDynamicMandatorySchemaAttributes(
    OPINION_TYPE,
  );
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const basicShape = {
    opinion: Yup.string(),
    explanation: Yup.string().nullable(),
    confidence: Yup.number(),
    x_opencti_workflow_id: Yup.object(),
  };
  const opinionValidator = useDynamicSchemaEditionValidation(OPINION_TYPE, basicShape);

  const queries = {
    fieldPatch: opinionMutationFieldPatch,
    relationAdd: opinionMutationRelationAdd,
    relationDelete: opinionMutationRelationDelete,
    editionFocus: opinionEditionOverviewFocus,
  };
  const editor = useFormEditor(opinion, false, queries, opinionValidator);

  const handleSubmitField = (name, value) => {
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    opinionValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: opinion.id,
            input: { key: name, value: finalValue ?? '' },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    createdBy: convertCreatedBy(opinion),
    objectMarking: convertMarkings(opinion),
    x_opencti_workflow_id: convertStatus(t_i18n, opinion),
    confidence: opinion.confidence,
    explanation: opinion.explanation,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={opinionValidator}
      onSubmit={() => {
      }}
    >
      {({ setFieldValue }) => (
        <div>
          <Form style={{ margin: '20px 0 20px 0' }}>
            <AlertConfidenceForEntity entity={opinion} />
            <OpenVocabField
              label={t_i18n('Opinion')}
              type="opinion-ov"
              name="opinion"
              required={(mandatoryAttributes.includes('opinion'))}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <Field
              component={MarkdownField}
              name="explanation"
              label={t_i18n('Explanation')}
              required={(mandatoryAttributes.includes('explanation'))}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="content"/>
              }
            />
            <ConfidenceField
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              entityType="Opinion"
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            {opinion.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Opinion"
                onFocus={editor.changeFocus}
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
            {userIsKnowledgeEditor && (
              <CreatedByField
                name="createdBy"
                required={(mandatoryAttributes.includes('createdBy'))}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus context={context} fieldName="createdBy"/>
                }
                onChange={editor.changeCreated}
              />
            )}
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              setFieldValue={setFieldValue}
              onChange={editor.changeMarking}
            />
          </Form>
        </div>
      )}
    </Formik>
  );
};

export default createFragmentContainer(OpinionEditionOverviewComponent, {
  opinion: graphql`
      fragment OpinionEditionOverview_opinion on Opinion {
          id
          opinion
          explanation
          confidence
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
