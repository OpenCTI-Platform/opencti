import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
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
    $input: StixMetaRelationshipAddInput
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

const noteValidation = (t) => Yup.object().shape({
  attribute_abstract: Yup.string().nullable(),
  content: Yup.string().required(t('This field is required')),
  created: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  confidence: Yup.number(),
  x_opencti_workflow_id: Yup.object(),
});

const NoteEditionOverviewComponent = (props) => {
  const { note, context } = props;
  const { t } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);

  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: noteEditionOverviewFocus,
      variables: {
        id: note.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name, value) => {
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    noteValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: noteMutationFieldPatch,
          variables: {
            id: note.id,
            input: { key: name, value: finalValue ?? '' },
          },
        });
      })
      .catch(() => false);
  };

  const handleChangeCreatedBy = (name, value) => {
    commitMutation({
      mutation: noteMutationFieldPatch,
      variables: {
        id: note.id,
        input: { key: 'createdBy', value: value.value || '' },
      },
    });
  };

  const handleChangeObjectMarking = (name, values) => {
    const currentMarkingDefinitions = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(note);
    const added = R.difference(values, currentMarkingDefinitions);
    const removed = R.difference(currentMarkingDefinitions, values);
    if (added.length > 0) {
      commitMutation({
        mutation: noteMutationRelationAdd,
        variables: {
          id: note.id,
          input: {
            toId: R.head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: noteMutationRelationDelete,
        variables: {
          id: note.id,
          toId: R.head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  };

  const objectMarking = convertMarkings(note);
  const createdBy = convertCreatedBy(note);
  const status = convertStatus(t, note);
  const initialValues = R.pipe(
    R.assoc('objectMarking', objectMarking),
    R.assoc('createdBy', createdBy),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc('created', buildDate(note.created)),
    R.pick([
      'attribute_abstract',
      'created',
      'createdBy',
      'content',
      'confidence',
      'objectOrganization',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(note);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={noteValidation(t)}
    >
      {({ setFieldValue }) => (
        <div>
          <Form style={{ margin: '0px 0 20px 0' }}>
            <Field
              component={DateTimePickerField}
              name="created"
              onFocus={handleChangeFocus}
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
              onFocus={handleChangeFocus}
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
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="content" />
              }
            />
            <ConfidenceField
              name="confidence"
              onFocus={handleChangeFocus}
              onChange={handleSubmitField}
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            {userIsKnowledgeEditor && <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              onChange={handleChangeCreatedBy}
            />}
            {note.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Note"
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
          </Form>
        </div>
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
        confidence
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
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
