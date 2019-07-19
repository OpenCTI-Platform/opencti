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
  sortWith,
  ascend,
  path,
  union,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import Autocomplete from '../../../../components/Autocomplete';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import {
  commitMutation,
  fetchQuery,
  WS_ACTIVATED,
} from '../../../../relay/environment';
import { killChainPhasesLinesSearchQuery } from '../../settings/kill_chain_phases/KillChainPhasesLines';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import AutocompleteCreate from '../../../../components/AutocompleteCreate';
import IdentityCreation, {
  identityCreationIdentitiesSearchQuery,
} from '../../common/identities/IdentityCreation';

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

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AttackPatternEditionOverview_attackPattern
      }
    }
  }
`;

export const attackPatternEditionOverviewFocus = graphql`
  mutation AttackPatternEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        ...AttackPatternEditionOverview_attackPattern
      }
    }
  }
`;

const attackPatternMutationRelationAdd = graphql`
  mutation AttackPatternEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    attackPatternEdit(id: $id) {
      relationAdd(input: $input) {
        node {
          ...AttackPatternEditionOverview_attackPattern
        }
      }
    }
  }
`;

const attackPatternMutationRelationDelete = graphql`
  mutation AttackPatternEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    attackPatternEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        node {
          ...AttackPatternEditionOverview_attackPattern
        }
      }
    }
  }
`;

const attackPatternValidation = t => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class AttackPatternEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      killChainPhases: [],
      markingDefinitions: [],
      identityCreation: false,
      identities: [],
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

  searchKillChainPhases(event) {
    fetchQuery(killChainPhasesLinesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const killChainPhases = pipe(
        pathOr([], ['killChainPhases', 'edges']),
        sortWith([ascend(path(['node', 'phase_order']))]),
        map(n => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(data);
      this.setState({
        killChainPhases: union(this.state.killChainPhases, killChainPhases),
      });
    });
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsLinesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map(n => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      this.setState({
        markingDefinitions: union(
          this.state.markingDefinitions,
          markingDefinitions,
        ),
      });
    });
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: attackPatternEditionOverviewFocus,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    attackPatternValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: attackPatternMutationFieldPatch,
          variables: {
            id: this.props.attackPattern.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { attackPattern } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], attackPattern),
      value: pathOr(null, ['createdByRef', 'node', 'id'], attackPattern),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], attackPattern),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.attackPattern.id,
            toRole: 'so',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.attackPattern.id,
            toRole: 'so',
            through: 'created_by_ref',
          },
        },
      });
    }
  }

  handleChangeKillChainPhases(name, values) {
    const { attackPattern } = this.props;
    const currentKillChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map(n => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);

    const added = difference(values, currentKillChainPhases);
    const removed = difference(currentKillChainPhases, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: head(added).value,
          input: {
            fromRole: 'kill_chain_phase',
            toId: this.props.attackPattern.id,
            toRole: 'phase_belonging',
            through: 'kill_chain_phases',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  handleChangeMarkingDefinition(name, values) {
    const { attackPattern } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: head(added).value,
          input: {
            fromRole: 'marking',
            toId: this.props.attackPattern.id,
            toRole: 'so',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const {
      t, attackPattern, editUsers, me,
    } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], attackPattern) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdByRef', 'node', 'name'],
          attackPattern,
        ),
        value: pathOr(null, ['createdByRef', 'node', 'id'], attackPattern),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          attackPattern,
        ),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map(n => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('killChainPhases', killChainPhases),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'description',
        'createdByRef',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(attackPattern);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={attackPatternValidation(t)}
          onSubmit={() => true}
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
                  name="killChainPhases"
                  component={Autocomplete}
                  multiple={true}
                  label={t('Kill chain phases')}
                  options={this.state.killChainPhases}
                  onInputChange={this.searchKillChainPhases.bind(this)}
                  onChange={this.handleChangeKillChainPhases.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="killChainPhases"
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

AttackPatternEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  attackPattern: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const AttackPatternEditionOverview = createFragmentContainer(
  AttackPatternEditionOverviewComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionOverview_attackPattern on AttackPattern {
        id
        name
        description
        createdByRef {
          node {
            id
            name
          }
          relation {
            id
          }
        }
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              phase_order
            }
            relation {
              id
            }
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
)(AttackPatternEditionOverview);
