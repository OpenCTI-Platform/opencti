import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { buildDate } from '../../../../utils/Time';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatedByField from '../../common/form/CreatedByField';
import useGranted, {
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/hooks/useGranted';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import { NoteEditionOverview_note$data } from './__generated__/NoteEditionOverview_note.graphql';
import SliderField from '../../../../components/SliderField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

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
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  handleClose: () => void;
}

const NoteEditionOverviewComponent: FunctionComponent<
NoteEditionOverviewProps
> = ({ note, context }) => {
  const { t } = useFormatter();

  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const basicShape = {
    content: Yup.string().min(2).required(t('This field is required')),
    created: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    attribute_abstract: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    note_types: Yup.array().nullable(),
    likelihood: Yup.number()
      .min(0)
      .max(100)
      .transform((value) => (Number.isNaN(value) ? null : value))
      .nullable(true),
    x_opencti_workflow_id: Yup.object(),
  };
  const noteValidator = useSchemaEditionValidation('Note', basicShape);

  const queries = {
    fieldPatch: noteMutationFieldPatch,
    relationAdd: noteMutationRelationAdd,
    relationDelete: noteMutationRelationDelete,
    editionFocus: noteEditionOverviewFocus,
  };
  const editor = useFormEditor(note, false, queries, noteValidator);

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
    x_opencti_workflow_id: convertStatus(t, note) as Option,
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
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Publication date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created" />
              ),
            }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="attribute_abstract"
            label={t('Abstract')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus
                context={context}
                fieldName="attribute_abstract"
              />
            }
          />
          <Field
            component={MarkDownField}
            name="content"
            label={t('Content')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="content" />
            }
          />
          <OpenVocabField
            label={t('Note types')}
            type="note_types_ov"
            name="note_types"
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
            variant="standard"
            name="likelihood"
            type="number"
            label={t('Likelihood')}
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
            style={{
              marginTop:
                note.workflowEnabled || userIsKnowledgeEditor ? 20 : 10,
              width: '100%',
            }}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
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
        content
        note_types
        confidence
        likelihood
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
