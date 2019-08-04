import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
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
import {
  commitMutation,
  fetchQuery,
  WS_ACTIVATED,
} from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import Autocomplete from '../../../components/Autocomplete';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import { markingDefinitionsSearchQuery } from '../settings/MarkingDefinitions';

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
        ...WorkspaceEditionOverview_workspace
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
        node {
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
        node {
          ...WorkspaceEditionOverview_workspace
        }
      }
    }
  }
`;

const workspaceValidation = t => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  workspace_class: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

class WorkspaceEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      identityCreation: false,
      identities: [],
      markingDefinitions: [],
    };
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsSearchQuery, {
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
        mutation: workspaceEditionOverviewFocus,
        variables: {
          id: this.props.workspace.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
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

  handleChangeMarkingDefinition(name, values) {
    const { workspace } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
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
          id: head(added).value,
          input: {
            fromRole: 'marking',
            toId: this.props.workspace.id,
            toRole: 'so',
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
    const {
      t, workspace, editUsers, me,
    } = this.props;
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
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
          render={() => (
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
              </Form>
            </div>
          )}
        />
      </div>
    );
  }
}

WorkspaceEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  workspace: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
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
