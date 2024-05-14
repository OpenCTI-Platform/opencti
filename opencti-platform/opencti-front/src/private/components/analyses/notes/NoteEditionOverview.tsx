import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { GenericContext } from '@components/common/model/GenericContextModel';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { buildDate } from '../../../../utils/Time';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatedByField from '../../common/form/CreatedByField';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import { NoteEditionOverview_note$data } from './__generated__/NoteEditionOverview_note.graphql';
import SliderField from '../../../../components/fields/SliderField';
import { useDynamicSchemaEditionValidation, useDynamicMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

export const noteMutationFieldPatch = graphql`
  mutation NoteEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    noteEdit(id: $id) {
      fieldPatch(input: $input) {
        ...NoteEditionOverview_note
        ...Note_note
      }
    }
  }
`;

export const noteEditionOverviewFocus = graphql`
  mutation NoteEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    noteEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const noteMutationRelationAdd = graphql`
  mutation NoteEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...NoteEditionOverview_note
        }
      }
    }
  }
`;

const noteMutationRelationDelete = graphql`
  mutation NoteEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

interface NoteEditionOverviewProps {
  note: NoteEditionOverview_note$data;
  context?: readonly (GenericContext | null)[] | null;
  handleClose: () => void;
}

export const NOTE_TYPE = 'Note';

const NoteEditionOverviewComponent: FunctionComponent<
NoteEditionOverviewProps
> = ({ note, context }) => {
  const { t_i18n } = useFormatter();

  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);

  const mandatoryAttributes = useDynamicMandatorySchemaAttributes(
    NOTE_TYPE,
  );
  const basicShape = {
    content: Yup.string().trim().min(2),
    created: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    attribute_abstract: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    note_types: Yup.array().nullable(),
    likelihood: Yup.number()
      .min(0)
      .max(100)
      .transform((value) => (Number.isNaN(value) ? null : value))
      .nullable(),
    x_opencti_workflow_id: Yup.object(),
  };
  const noteValidator = useDynamicSchemaEditionValidation(NOTE_TYPE, basicShape);

  const queries = {
    fieldPatch: noteMutationFieldPatch,
    relationAdd: noteMutationRelationAdd,
    relationDelete: noteMutationRelationDelete,
    editionFocus: noteEditionOverviewFocus,
  };
  const editor = useFormEditor(note as GenericData, false, queries, noteValidator);

  const handleSubmitField = (
    name: string,
    value: Option | string | string[] | number | number[],
  ) => {
    let finalValue = value ?? '';
    if (name === 'x_opencti_workflow_id') {
      finalValue = (value as Option).value;
    }
    noteValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: note.id,
            input: [{ key: name, value: finalValue }],
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    created: buildDate(note.created),
    attribute_abstract: note.attribute_abstract,
    content: note.content,
    confidence: note.confidence,
    note_types: note.note_types ?? [],
    likelihood: note.likelihood,
    createdBy: convertCreatedBy(note) as Option,
    objectMarking: convertMarkings(note),
    x_opencti_workflow_id: convertStatus(t_i18n, note) as Option,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={noteValidator}
      onSubmit={() => {}}
    >
      {({ setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={note} />
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Publication date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created"/>
              ),
            }}
          />
          <Field
            component={TextField}
            name="attribute_abstract"
            label={t_i18n('Abstract')}
            required={(mandatoryAttributes.includes('attribute_abstract'))}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
            helperText={
              <SubscriptionFocus
                context={context}
                fieldName="attribute_abstract"
              />
            }
          />
          <Field
            component={MarkdownField}
            name="content"
            label={t_i18n('Content')}
            required={(mandatoryAttributes.includes('content'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="content" />
            }
          />
          <OpenVocabField
            label={t_i18n('Note types')}
            type="note_types_ov"
            name="note_types"
            required={(mandatoryAttributes.includes('note_types'))}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Note"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={SliderField}
            name="likelihood"
            type="number"
            label={t_i18n('Likelihood')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helpertext={
              <SubscriptionFocus context={context} fieldName="likelihood" />
            }
          />
          {userIsKnowledgeEditor && (
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={{ marginTop: 10, width: '100%' }}
              setFieldValue={setFieldValue}
              onChange={editor.changeCreated}
            />
          )}
          {note.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Note"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_workflow_id"
                />
              }
            />
          )}
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={{
              marginTop:
                note.workflowEnabled || userIsKnowledgeEditor ? 20 : 10,
              width: '100%',
            }}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
        </Form>
      )}
    </Formik>
  );
};

const NoteEditionOverview = createFragmentContainer(
  NoteEditionOverviewComponent,
  {
    note: graphql`
      fragment NoteEditionOverview_note on Note {
        id
        created
        attribute_abstract
        entity_type
        content
        note_types
        confidence
        likelihood
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        createdBy {
          id
          name
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
  },
);

export default NoteEditionOverview;
