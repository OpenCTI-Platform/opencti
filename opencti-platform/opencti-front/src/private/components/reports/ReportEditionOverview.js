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
  union,
} from 'ramda';
import * as Yup from 'yup';
import { dateFormat } from '../../../utils/Time';
import {
  commitMutation,
  fetchQuery,
  WS_ACTIVATED,
} from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import Autocomplete from '../../../components/Autocomplete';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';
import { SubscriptionFocus } from '../../../components/Subscription';
import AutocompleteCreate from '../../../components/AutocompleteCreate';
import { markingDefinitionsLinesSearchQuery } from '../settings/marking_definitions/MarkingDefinitionsLines';
import IdentityCreation, {
  identityCreationIdentitiesSearchQuery,
} from '../common/identities/IdentityCreation';
import DatePickerField from '../../../components/DatePickerField';

const styles = theme => ({
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
        ...ReportEditionOverview_report
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
        node {
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
        node {
          ...ReportEditionOverview_report
        }
      }
    }
  }
`;

const reportValidation = t => Yup.object().shape({
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
  constructor(props) {
    super(props);
    this.state = {
      identityCreation: false,
      identities: [],
      markingDefinitions: [],
    };
  }

  searchIdentities(event) {
    fetchQuery(identityCreationIdentitiesSearchQuery, {
      search: event.target.value,
      first: 10,
    }).then((data) => {
      const identities = pipe(
        pathOr([], ['identities', 'edges']),
        map(n => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({ identities: union(this.state.identities, identities) });
    });
  }

  handleOpenIdentityCreation(inputValue) {
    this.setState({ identityCreation: true, identityInput: inputValue });
  }

  handleCloseIdentityCreation() {
    this.setState({ identityCreation: false });
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsLinesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map(n => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      this.setState({ markingDefinitions });
    });
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
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
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.report.id,
            toRole: 'so',
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
      commitMutation({
        mutation: reportMutationRelationAdd,
        variables: {
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.report.id,
            toRole: 'so',
            through: 'created_by_ref',
          },
        },
      });
    }
  }

  handleChangeMarkingDefinition(name, values) {
    const { report } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
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
          id: head(added).value,
          input: {
            fromRole: 'marking',
            toId: this.props.report.id,
            toRole: 'so',
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
    const {
      t, report, editUsers, me,
    } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], report) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], report),
        value: pathOr(null, ['createdByRef', 'node', 'id'], report),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], report),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
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
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={reportValidation(t)}
          render={({ setFieldValue }) => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="name"
                  component={TextField}
                  label={t('Name')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="name"
                    />
                  }
                />
                <Field
                  name="report_class"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Report type')}
                  fullWidth={true}
                  inputProps={{
                    name: 'report_class',
                    id: 'report_class',
                  }}
                  containerstyle={{ marginTop: 10, width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="report_class"
                    />
                  }
                >
                  <MenuItem value="internal">{t('Internal report')}</MenuItem>
                  <MenuItem value="external">{t('External source')}</MenuItem>
                </Field>
                <Field
                  name="published"
                  component={DatePickerField}
                  label={t('Publication date')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="published"
                    />
                  }
                />
                <Field
                  name="description"
                  component={TextField}
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="description"
                    />
                  }
                />
                <Field
                  name="createdByRef"
                  component={AutocompleteCreate}
                  multiple={false}
                  handleCreate={this.handleOpenIdentityCreation.bind(this)}
                  label={t('Author')}
                  options={this.state.identities}
                  onInputChange={this.searchIdentities.bind(this)}
                  onChange={this.handleChangeCreatedByRef.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="createdByRef"
                    />
                  }
                />
                <Field
                  name="markingDefinitions"
                  component={Autocomplete}
                  multiple={true}
                  label={t('Marking')}
                  options={this.state.markingDefinitions}
                  onInputChange={this.searchMarkingDefinitions.bind(this)}
                  onChange={this.handleChangeMarkingDefinition.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="markingDefinitions"
                    />
                  }
                />
                <Field
                  name="object_status"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Processing status')}
                  fullWidth={true}
                  inputProps={{
                    name: 'object_status',
                    id: 'object_status',
                  }}
                  containerstyle={{ width: '100%', marginTop: 10 }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  name="source_confidence_level"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Confidence level')}
                  fullWidth={true}
                  inputProps={{
                    name: 'source_confidence_level',
                    id: 'source_confidence_level',
                  }}
                  containerstyle={{ width: '100%', marginTop: 10 }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  <MenuItem key="5" value="5">
                    {t('confidence_5')}
                  </MenuItem>
                </Field>
              </Form>
              <IdentityCreation
                contextual={true}
                inputValue={this.state.identityInput}
                open={this.state.identityCreation}
                handleClose={this.handleCloseIdentityCreation.bind(this)}
                creationCallback={(data) => {
                  setFieldValue('createdByRef', {
                    label: data.identityAdd.name,
                    value: data.identityAdd.id,
                  });
                  this.handleChangeCreatedByRef('createdByRef', {
                    label: data.identityAdd.name,
                    value: data.identityAdd.id,
                  });
                }}
              />
            </div>
          )}
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
  editUsers: PropTypes.array,
  me: PropTypes.object,
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
