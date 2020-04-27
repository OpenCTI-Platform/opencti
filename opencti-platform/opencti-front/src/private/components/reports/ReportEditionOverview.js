import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
  difference,
  head,
} from 'ramda';
import * as Yup from 'yup';
import { dateFormat } from '../../../utils/Time';
import {
  QueryRenderer,
  commitMutation,
} from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import { SubscriptionFocus } from '../../../components/Subscription';
import DatePickerField from '../../../components/DatePickerField';
import { attributesQuery } from '../settings/attributes/AttributesLines';
import Loader from '../../../components/Loader';
import CreatedByRefField from '../common/form/CreatedByRefField';
import MarkingDefinitionsField from '../common/form/MarkingDefinitionsField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
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
});

export const reportMutationFieldPatch = graphql`
  mutation ReportEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ReportEditionOverview_report
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
    $input: RelationAddInput!
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
    $relationId: ID!
  ) {
    reportEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...ReportEditionOverview_report
      }
    }
  }
`;

const reportValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  report_class: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  object_status: Yup.number(),
  source_confidence_level: Yup.number(),
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

  handleSubmitField(name, value) {
    reportValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: reportMutationFieldPatch,
          variables: { id: this.props.report.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { report } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], report),
      value: pathOr(null, ['createdByRef', 'node', 'id'], report),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], report),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: reportMutationRelationAdd,
        variables: {
          id: this.props.report.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: reportMutationRelationDelete,
        variables: {
          id: this.props.report.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: reportMutationRelationAdd,
          variables: {
            id: this.props.report.id,
            input: {
              fromRole: 'so',
              toId: value.value,
              toRole: 'creator',
              through: 'created_by_ref',
            },
          },
        });
      }
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { report } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(report);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: reportMutationRelationAdd,
        variables: {
          id: this.props.report.id,
          input: {
            fromRole: 'so',
            toId: head(added).value,
            toRole: 'marking',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: reportMutationRelationDelete,
        variables: {
          id: this.props.report.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, report, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], report) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], report),
        value: pathOr(null, ['createdByRef', 'node', 'id'], report),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], report),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(report);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      assoc('published', dateFormat(report.published)),
      pick([
        'name',
        'published',
        'description',
        'report_class',
        'createdByRef',
        'markingDefinitions',
        'object_status',
        'source_confidence_level',
      ]),
    )(report);
    return (
      <div>
        <QueryRenderer
          query={attributesQuery}
          variables={{ type: 'report_class' }}
          render={({ props }) => {
            if (props && props.attributes) {
              const reportClassesEdges = props.attributes.edges;
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={reportValidation(t)}
                >
                  {({ setFieldValue }) => (
                    <div>
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          component={TextField}
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
                        <Field
                          component={SelectField}
                          name="report_class"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Report type')}
                          fullWidth={true}
                          containerstyle={{ marginTop: 20, width: '100%' }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="report_class"
                            />
                          }
                        >
                          {reportClassesEdges.map((reportClassEdge) => (
                            <MenuItem
                              key={reportClassEdge.node.value}
                              value={reportClassEdge.node.value}
                            >
                              {reportClassEdge.node.value}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={DatePickerField}
                          name="published"
                          label={t('Publication date')}
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName="published"
                            />
                          }
                        />
                        <Field
                          component={TextField}
                          name="description"
                          label={t('Description')}
                          fullWidth={true}
                          multiline={true}
                          rows="4"
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName="description"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          name="object_status"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Processing status')}
                          fullWidth={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="object_status"
                            />
                          }
                        >
                          <MenuItem key="0" value="0">
                            {t('report_status_0')}
                          </MenuItem>
                          <MenuItem key="1" value="1">
                            {t('report_status_1')}
                          </MenuItem>
                          <MenuItem key="2" value="2">
                            {t('report_status_2')}
                          </MenuItem>
                          <MenuItem key="3" value="3">
                            {t('report_status_3')}
                          </MenuItem>
                        </Field>
                        <Field
                          component={SelectField}
                          name="source_confidence_level"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Confidence level')}
                          fullWidth={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="source_confidence_level"
                            />
                          }
                        >
                          <MenuItem key="1" value="1">
                            {t('confidence_1')}
                          </MenuItem>
                          <MenuItem key="2" value="2">
                            {t('confidence_2')}
                          </MenuItem>
                          <MenuItem key="3" value="3">
                            {t('confidence_3')}
                          </MenuItem>
                          <MenuItem key="4" value="4">
                            {t('confidence_4')}
                          </MenuItem>
                        </Field>
                        <CreatedByRefField
                          name="createdByRef"
                          style={{ marginTop: 20, width: '100%' }}
                          setFieldValue={setFieldValue}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="createdByRef"
                            />
                          }
                          onChange={this.handleChangeCreatedByRef.bind(this)}
                        />
                        <MarkingDefinitionsField
                          name="markingDefinitions"
                          style={{ marginTop: 20, width: '100%' }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="markingDefinitions"
                            />
                          }
                          onChange={this.handleChangeMarkingDefinitions.bind(
                            this,
                          )}
                        />
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
        report_class
        published
        object_status
        source_confidence_level
        createdByRef {
          node {
            id
            name
            entity_type
          }
          relation {
            id
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
              definition_type
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportEditionOverview);
