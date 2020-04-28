import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
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
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
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

export const workspaceMutationFieldPatch = graphql`
  mutation WorkspaceEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    workspaceEdit(id: $id) {
      fieldPatch(input: $input) {
        ...WorkspaceExploreSpace_workspace
      }
    }
  }
`;

export const workspaceEditionOverviewFocus = graphql`
  mutation WorkspaceEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    workspaceEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const workspaceMutationRelationAdd = graphql`
  mutation WorkspaceEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    workspaceEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...WorkspaceEditionOverview_workspace
        }
      }
    }
  }
`;

const workspaceMutationRelationDelete = graphql`
  mutation WorkspaceEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    workspaceEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...WorkspaceEditionOverview_workspace
      }
    }
  }
`;

const workspaceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  workspace_class: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

class WorkspaceEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: workspaceEditionOverviewFocus,
      variables: {
        id: this.props.workspace.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    workspaceValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: workspaceMutationFieldPatch,
          variables: {
            id: this.props.workspace.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeMarkingDefinitions(name, values) {
    const { workspace } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(workspace);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: workspaceMutationRelationAdd,
        variables: {
          id: this.props.workspace.id,
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
        mutation: workspaceMutationRelationDelete,
        variables: {
          id: this.props.workspace.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, workspace, context } = this.props;
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(workspace);
    const initialValues = pipe(
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'description', 'markingDefinitions']),
    )(workspace);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={workspaceValidation(t)}
        >
          {() => (
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
                    <SubscriptionFocus context={context} fieldName="name" />
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
                <MarkingDefinitionsField
                  name="markingDefinitions"
                  style={{ marginTop: 20, width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="markingDefinitions"
                    />
                  }
                  onChange={this.handleChangeMarkingDefinitions.bind(this)}
                />
              </Form>
            </div>
          )}
        </Formik>
      </div>
    );
  }
}

WorkspaceEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  workspace: PropTypes.object,
  context: PropTypes.array,
};

const WorkspaceEditionOverview = createFragmentContainer(
  WorkspaceEditionOverviewComponent,
  {
    workspace: graphql`
      fragment WorkspaceEditionOverview_workspace on Workspace {
        id
        name
        description
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
)(WorkspaceEditionOverview);
