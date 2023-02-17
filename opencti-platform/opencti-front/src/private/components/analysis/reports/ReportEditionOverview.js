import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { buildDate, parse } from '../../../../utils/Time';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import Loader from '../../../../components/Loader';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertAssignees, convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { vocabulariesQuery } from '../../settings/attributes/VocabulariesLines';
import OpenVocabField from '../../common/form/OpenVocabField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';

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
    $input: StixMetaRelationshipAddInput
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

const reportValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  report_types: Yup.array().required(t('This field is required')),
  confidence: Yup.number(),
  description: Yup.string().nullable(),
  x_opencti_workflow_id: Yup.object(),
});

const ReportEditionOverviewComponent = (props) => {
  const { report, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: reportEditionOverviewFocus,
    variables: {
      id: report.id,
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
      R.assoc('published', parse(values.published).format()),
      R.assoc('report_types', values.report_types),
      R.assoc('objectAssignee', R.pluck('value', values.objectAssignee)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: reportMutationFieldPatch,
      variables: {
        id: report.id,
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
      reportValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: reportMutationFieldPatch,
            variables: {
              id: report.id,
              input: {
                key: name,
                value: finalValue,
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: reportMutationFieldPatch,
        variables: {
          id: report.id,
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
      )(report);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: reportMutationRelationAdd,
          variables: {
            id: report.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: reportMutationRelationDelete,
          variables: {
            id: report.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const handleChangeObjectAssignee = (name, values) => {
    if (!enableReferences) {
      const currentAssignees = R.pipe(
        R.pathOr([], ['objectAssignee', 'edges']),
        R.map((n) => ({
          label: n.node.name,
          value: n.node.id,
        })),
      )(report);
      const added = R.difference(values, currentAssignees);
      const removed = R.difference(currentAssignees, values);
      if (added.length > 0) {
        commitMutation({
          mutation: reportMutationRelationAdd,
          variables: {
            id: report.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-assignee',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: reportMutationRelationDelete,
          variables: {
            id: report.id,
            toId: R.head(removed).value,
            relationship_type: 'object-assignee',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(report);
  const objectMarking = convertMarkings(report);
  const objectAssignee = convertAssignees(report);
  const status = convertStatus(t, report);
  const initialValues = R.pipe(
    R.assoc('published', buildDate(report.published)),
    R.assoc('report_types', report.report_types ?? []),
    R.assoc('objectAssignee', objectAssignee),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.pick([
      'name',
      'published',
      'description',
      'report_types',
      'createdBy',
      'objectMarking',
      'objectAssignee',
      'confidence',
      'x_opencti_workflow_id',
    ]),
  )(report);
  return (
    <div>
      <QueryRenderer
        query={vocabulariesQuery}
        variables={{ category: 'report_types_ov' }}
        render={({ props: rendererProps }) => {
          if (rendererProps && rendererProps.vocabularies) {
            return (
              <Formik
                enableReinitialize={true}
                initialValues={initialValues}
                validationSchema={reportValidation(t)}
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
                        <SubscriptionFocus
                          context={context}
                          fieldName="name"
                        />
                      }
                    />
                    <Field
                      component={DateTimePickerField}
                      name="published"
                      onFocus={handleChangeFocus}
                      onSubmit={handleSubmitField}
                      TextFieldProps={{
                        label: t('Publication date'),
                        variant: 'standard',
                        fullWidth: true,
                        style: { marginTop: 20 },
                        helperText: (
                          <SubscriptionFocus
                            context={context}
                            fieldName="published"
                          />
                        ),
                      }}
                    />
                    <OpenVocabField
                      label={t('Report types')}
                      type="report_types_ov"
                      name="report_types"
                      onSubmit={handleSubmitField}
                      onChange={(name, value) => setFieldValue(name, value)}
                      containerStyle={fieldSpacingContainerStyle}
                      variant="edit"
                      multiple={true}
                      editContext={context}
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
                    />
                    <ObjectAssigneeField
                      name="objectAssignee"
                      style={{ marginTop: 20, width: '100%' }}
                      helpertext={
                        <SubscriptionFocus
                          context={context}
                          fieldname="objectAssignee"
                        />
                      }
                      onChange={handleChangeObjectAssignee}
                    />
                    {report.workflowEnabled && (
                      <StatusField
                        name="x_opencti_workflow_id"
                        type="Report"
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
                        id={report.id}
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
    </div>
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
        objectAssignee {
          edges {
            node {
              id
              name
              entity_type
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
