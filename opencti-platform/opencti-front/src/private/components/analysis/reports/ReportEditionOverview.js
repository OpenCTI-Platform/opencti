import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import { buildDate, parse } from '../../../../utils/Time';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import Security, { SETTINGS_SETLABELS } from '../../../../utils/Security';
import AutocompleteField from '../../../../components/AutocompleteField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

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
  description: Yup.string().nullable(),
  confidence: Yup.number(),
  x_opencti_workflow_id: Yup.object(),
});

class ReportEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: reportEditionOverviewFocus,
      variables: {
        id: this.props.report.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('published', parse(values.published).format()),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('report_types', R.pluck('value', values.report_types)),
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
        id: this.props.report.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      if (name === 'report_types') {
        finalValue = R.pluck('value', value);
      }
      reportValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: reportMutationFieldPatch,
            variables: {
              id: this.props.report.id,
              input: {
                key: name,
                value: finalValue,
              },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: reportMutationFieldPatch,
        variables: {
          id: this.props.report.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { report } = this.props;
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
            id: this.props.report.id,
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
            id: this.props.report.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const { t, report, context, enableReferences, classes } = this.props;
    const createdBy = convertCreatedBy(report);
    const objectMarking = convertMarkings(report);
    const status = convertStatus(t, report);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('published', buildDate(report.published)),
      R.assoc('x_opencti_workflow_id', status),
      R.assoc(
        'report_types',
        (report.report_types || []).map((n) => ({ label: n, value: n })),
      ),
      R.pick([
        'name',
        'published',
        'description',
        'report_types',
        'createdBy',
        'objectMarking',
        'confidence',
        'x_opencti_workflow_id',
      ]),
    )(report);
    return (
      <div>
        <QueryRenderer
          query={attributesQuery}
          variables={{ key: 'report_types' }}
          render={({ props }) => {
            if (props && props.runtimeAttributes) {
              const reportEdges = props.runtimeAttributes.edges.map(
                (e) => e.node.value,
              );
              const elements = R.uniq([
                ...reportEdges,
                'threat-report',
                'internal-report',
              ]);
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={reportValidation(t)}
                  onSubmit={this.onSubmit.bind(this)}
                >
                  {({
                    submitForm,
                    isSubmitting,
                    validateForm,
                    setFieldValue,
                    values,
                  }) => (
                    <div>
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          component={TextField}
                          variant="standard"
                          name="name"
                          label={t('Name')}
                          fullWidth={true}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName="name"
                            />
                          }
                        />
                        <Security
                          needs={[SETTINGS_SETLABELS]}
                          placeholder={
                            <Field
                              component={AutocompleteField}
                              onChange={this.handleSubmitField.bind(this)}
                              style={{ marginTop: 20 }}
                              name="report_types"
                              multiple={true}
                              createLabel={t('Add')}
                              textfieldprops={{
                                variant: 'standard',
                                label: t('Report types'),
                                helperText: (
                                  <SubscriptionFocus
                                    context={context}
                                    fieldName="report_types"
                                  />
                                ),
                              }}
                              options={elements.map((n) => ({
                                id: n,
                                value: n,
                                label: n,
                              }))}
                              renderOption={(optionProps, option) => (
                                <li {...optionProps}>
                                  <div className={classes.icon}>
                                    <ItemIcon type="attribute" />
                                  </div>
                                  <div className={classes.text}>
                                    {option.label}
                                  </div>
                                </li>
                              )}
                              classes={{
                                clearIndicator: classes.autoCompleteIndicator,
                              }}
                            />
                          }
                        >
                          <Field
                            component={AutocompleteFreeSoloField}
                            onChange={this.handleSubmitField.bind(this)}
                            style={{ marginTop: 20 }}
                            name="report_types"
                            multiple={true}
                            createLabel={t('Add')}
                            textfieldprops={{
                              variant: 'standard',
                              label: t('Report types'),
                              helperText: (
                                <SubscriptionFocus
                                  context={context}
                                  fieldName="report_types"
                                />
                              ),
                            }}
                            options={elements.map((n) => ({
                              id: n,
                              value: n,
                              label: n,
                            }))}
                            renderOption={(optionProps, option) => (
                              <li {...optionProps}>
                                <div className={classes.icon}>
                                  <ItemIcon type="attribute" />
                                </div>
                                <div className={classes.text}>
                                  {option.label}
                                </div>
                              </li>
                            )}
                            classes={{
                              clearIndicator: classes.autoCompleteIndicator,
                            }}
                          />
                        </Security>
                        <ConfidenceField
                          name="confidence"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Confidence')}
                          fullWidth={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                          editContext={context}
                          variant="edit"
                        />
                        <Field
                          component={DateTimePickerField}
                          name="published"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
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
                        <Field
                          component={MarkDownField}
                          name="description"
                          label={t('Description')}
                          fullWidth={true}
                          multiline={true}
                          rows="4"
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                        />
                        {report.workflowEnabled && (
                          <StatusField
                            name="x_opencti_workflow_id"
                            type="Report"
                            onFocus={this.handleChangeFocus.bind(this)}
                            onChange={this.handleSubmitField.bind(this)}
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
                          onChange={this.handleChangeCreatedBy.bind(this)}
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
                          onChange={this.handleChangeObjectMarking.bind(this)}
                        />
                        {enableReferences && (
                          <CommitMessage
                            submitForm={submitForm}
                            disabled={isSubmitting}
                            validateForm={validateForm}
                            setFieldValue={setFieldValue}
                            values={values}
                            id={report.id}
                          />
                        )}
                      </Form>
                    </div>
                  )}
                </Formik>
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

ReportEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  report: PropTypes.object,
  context: PropTypes.array,
};

const ReportEditionOverview = createFragmentContainer(
  ReportEditionOverviewComponent,
  {
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
              definition
              definition_type
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
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportEditionOverview);
