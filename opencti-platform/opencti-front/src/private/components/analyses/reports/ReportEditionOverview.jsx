import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Button } from '@mui/material';
import { buildDate, parse } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkdownField from '../../../../components/MarkdownField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertAssignees, convertCreatedBy, convertMarkings, convertParticipants, convertStatus } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import ReportPopoverDeletion from './ReportPopoverDeletion';

export const reportMutationFieldPatch = graphql`
  mutation ReportEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    reportEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        x_opencti_graph_data
        ...ReportEditionOverview_report
        ...Report_report
      }
    }
  }
`;

export const reportEditionOverviewFocus = graphql`
  mutation ReportEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    reportEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const reportMutationRelationAdd = graphql`
  mutation ReportEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ReportEditionOverview_report
        }
      }
    }
  }
`;

const reportMutationRelationDelete = graphql`
  mutation ReportEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    reportEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ReportEditionOverview_report
      }
    }
  }
`;

const ReportEditionOverviewComponent = (props) => {
  const { report, enableReferences, context, handleClose } = props;
  const [displayDelete, setDisplayDelete] = useState(false);
  const { t_i18n } = useFormatter();

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const basicShape = {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    published: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t_i18n('This field is required')),
    report_types: Yup.array().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const reportValidator = useSchemaEditionValidation('Report', basicShape);

  const queries = {
    fieldPatch: reportMutationFieldPatch,
    relationAdd: reportMutationRelationAdd,
    relationDelete: reportMutationRelationDelete,
    editionFocus: reportEditionOverviewFocus,
  };
  const editor = useFormEditor(
    report,
    enableReferences,
    queries,
    reportValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('published', parse(values.published).format()),
      R.assoc('report_types', values.report_types),
      R.assoc('objectAssignee', R.pluck('value', values.objectAssignee)),
      R.assoc('objectParticipant', R.pluck('value', values.objectParticipant)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: report.id,
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
      reportValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: report.id,
              input: { key: name, value: finalValue },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('published', buildDate(report.published)),
    R.assoc('report_types', report.report_types ?? []),
    R.assoc('objectAssignee', convertAssignees(report)),
    R.assoc('objectParticipant', convertParticipants(report)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, report)),
    R.assoc('createdBy', convertCreatedBy(report)),
    R.assoc('objectMarking', convertMarkings(report)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'published',
      'description',
      'report_types',
      'createdBy',
      'objectMarking',
      'objectAssignee',
      'objectParticipant',
      'confidence',
      'x_opencti_reliability',
      'x_opencti_workflow_id',
    ]),
  )(report);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={reportValidator}
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
          <AlertConfidenceForEntity entity={report} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={DateTimePickerField}
            name="published"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Publication date'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="published"/>
              ),
            }}
          />
          <OpenVocabField
            label={t_i18n('Report types')}
            type="report_types_ov"
            name="report_types"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Reliability')}
            type="reliability_ov"
            name="x_opencti_reliability"
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Report"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectParticipant" />
            }
            onChange={editor.changeParticipant}
          />
          {report.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Report"
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
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
            setFieldValue={setFieldValue}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
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
              id={report.id}
              deleteBtn={<>
                <Button
                  onClick={handleOpenDelete}
                  variant='contained'
                  color='error'
                >
                  {t_i18n('Delete')}
                </Button>
                <ReportPopoverDeletion
                  reportId={report.id}
                  displayDelete={displayDelete}
                  handleClose={handleClose}
                  handleCloseDelete={handleCloseDelete}
                />
              </>}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(ReportEditionOverviewComponent, {
  report: graphql`
    fragment ReportEditionOverview_report on Report {
      id
      name
      description
      report_types
      published
      confidence
      x_opencti_reliability
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
      objectAssignee {
        id
        name
        entity_type
      }
      objectParticipant {
        id
        name
        entity_type
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
