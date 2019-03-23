import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, map, pathOr, pipe, pick,
  difference, head, union,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../components/i18n';
import Autocomplete from '../../../components/Autocomplete';
import TextField from '../../../components/TextField';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, fetchQuery, WS_ACTIVATED } from '../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../marking_definition/MarkingDefinitionsLines';
import AutocompleteCreate from '../../../components/AutocompleteCreate';
import IdentityCreation, { identityCreationIdentitiesSearchQuery } from '../identity/IdentityCreation';

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

const intrusionSetMutationFieldPatch = graphql`
    mutation IntrusionSetEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
        intrusionSetEdit(id: $id) {
            fieldPatch(input: $input) {
                ...IntrusionSetEditionOverview_intrusionSet
            }
        }
    }
`;

export const intrusionSetEditionOverviewFocus = graphql`
    mutation IntrusionSetEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
        intrusionSetEdit(id: $id) {
            contextPatch(input : $input) {
                ...IntrusionSetEditionOverview_intrusionSet
            }
        }
    }
`;

const intrusionSetMutationRelationAdd = graphql`
    mutation IntrusionSetEditionOverviewRelationAddMutation($id: ID!, $input: RelationAddInput!) {
        intrusionSetEdit(id: $id) {
            relationAdd(input: $input) {
                node {
                    ...IntrusionSetEditionOverview_intrusionSet
                }
            }
        }
    }
`;

const intrusionSetMutationRelationDelete = graphql`
    mutation IntrusionSetEditionOverviewRelationDeleteMutation($id: ID!, $relationId: ID!) {
        intrusionSetEdit(id: $id) {
            relationDelete(relationId: $relationId) {
                node {
                    ...IntrusionSetEditionOverview_intrusionSet
                }
            }
        }
    }
`;

const intrusionSetValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(500, t('The value is too long'))
    .required(t('This field is required')),
});

class IntrusionSetEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      killChainPhases: [], markingDefinitions: [], identityCreation: false, identities: [],
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
    fetchQuery(markingDefinitionsLinesSearchQuery, { search: event.target.value })
      .then((data) => {
        const markingDefinitions = pipe(
          pathOr([], ['markingDefinitions', 'edges']),
          map(n => ({ label: n.node.definition, value: n.node.id })),
        )(data);
        this.setState({
          markingDefinitions: union(this.state.markingDefinitions, markingDefinitions),
        });
      });
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: intrusionSetEditionOverviewFocus,
        variables: {
          id: this.props.intrusionSet.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    intrusionSetValidation(this.props.t).validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        mutation: intrusionSetMutationFieldPatch,
        variables: { id: this.props.intrusionSet.id, input: { key: name, value } },
      });
    }).catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { intrusionSet } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], intrusionSet),
      value: pathOr(null, ['createdByRef', 'node', 'id'], intrusionSet),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], intrusionSet),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: intrusionSetMutationRelationAdd,
        variables: {
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.intrusionSet.id,
            toRole: 'so',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: intrusionSetMutationRelationDelete,
        variables: {
          id: this.props.intrusionSet.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      commitMutation({
        mutation: intrusionSetMutationRelationAdd,
        variables: {
          id: value.value,
          input: {
            fromRole: 'creator',
            toId: this.props.intrusionSet.id,
            toRole: 'so',
            through: 'created_by_ref',
          },
        },
      });
    }
  }

  handleChangeMarkingDefinition(name, values) {
    const { intrusionSet } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({ label: n.node.definition, value: n.node.id, relationId: n.relation.id })),
    )(intrusionSet);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: intrusionSetMutationRelationAdd,
        variables: {
          id: head(added).value,
          input: {
            fromRole: 'marking',
            toId: this.props.intrusionSet.id,
            toRole: 'so',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: intrusionSetMutationRelationDelete,
        variables: {
          id: this.props.intrusionSet.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const {
      t, intrusionSet, editUsers, me,
    } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], intrusionSet) === null ? '' : {
      label: pathOr(null, ['createdByRef', 'node', 'name'], intrusionSet),
      value: pathOr(null, ['createdByRef', 'node', 'id'], intrusionSet),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], intrusionSet),
    };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map(n => ({ label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`, value: n.node.id, relationId: n.relation.id })),
    )(intrusionSet);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map(n => ({ label: n.node.definition, value: n.node.id, relationId: n.relation.id })),
    )(intrusionSet);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('killChainPhases', killChainPhases),
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'description', 'createdByRef', 'killChainPhases', 'markingDefinitions']),
    )(intrusionSet);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={intrusionSetValidation(t)}
          onSubmit={() => true}
          render={({ setFieldValue }) => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field name='name' component={TextField} label={t('Name')} fullWidth={true}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='name'/>}/>
                <Field name='description' component={TextField} label={t('Description')}
                       fullWidth={true} multiline={true} rows='4' style={{ marginTop: 10 }}
                       onFocus={this.handleChangeFocus.bind(this)}
                       onSubmit={this.handleSubmitField.bind(this)}
                       helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='description'/>}/>
                <Field
                  name='createdByRef'
                  component={AutocompleteCreate}
                  multiple={false}
                  handleCreate={this.handleOpenIdentityCreation.bind(this)}
                  label={t('Author')}
                  options={this.state.identities}
                  onInputChange={this.searchIdentities.bind(this)}
                  onChange={this.handleChangeCreatedByRef.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='createdByRef'/>}
                />
                <Field
                  name='markingDefinitions'
                  component={Autocomplete}
                  multiple={true}
                  label={t('Marking')}
                  options={this.state.markingDefinitions}
                  onInputChange={this.searchMarkingDefinitions.bind(this)}
                  onChange={this.handleChangeMarkingDefinition.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='markingDefinitions'/>}
                />
              </Form>
              <IdentityCreation
                contextual={true}
                inputValue={this.state.identityInput}
                open={this.state.identityCreation}
                handleClose={this.handleCloseIdentityCreation.bind(this)}
                creationCallback={(data) => {
                  setFieldValue('createdByRef', { label: data.identityAdd.name, value: data.identityAdd.id });
                }}
              />
            </div>
          )}
        />
      </div>
    );
  }
}

IntrusionSetEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  intrusionSet: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const IntrusionSetEditionOverview = createFragmentContainer(IntrusionSetEditionOverviewComponent, {
  intrusionSet: graphql`
      fragment IntrusionSetEditionOverview_intrusionSet on IntrusionSet {
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
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IntrusionSetEditionOverview);
