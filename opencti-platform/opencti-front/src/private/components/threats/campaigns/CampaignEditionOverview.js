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
import { markingDefinitionsSearchQuery } from '../../settings/MarkingDefinitions';
import AutocompleteCreate from '../../../../components/AutocompleteCreate';
import IdentityCreation, {
  identityCreationIdentitiesSearchQuery,
} from '../../common/identities/IdentityCreation';

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

const campaignMutationFieldPatch = graphql`
  mutation CampaignEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    campaignEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CampaignEditionOverview_campaign
      }
    }
  }
`;

export const campaignEditionOverviewFocus = graphql`
  mutation CampaignEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    campaignEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const campaignMutationRelationAdd = graphql`
  mutation CampaignEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    campaignEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CampaignEditionOverview_campaign
        }
      }
    }
  }
`;

const campaignMutationRelationDelete = graphql`
  mutation CampaignEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    campaignEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...CampaignEditionOverview_campaign
      }
    }
  }
`;

const campaignValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class CampaignEditionOverviewComponent extends Component {
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
        map((n) => ({ label: n.node.name, value: n.node.id })),
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
    fetchQuery(markingDefinitionsSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map((n) => ({ label: n.node.definition, value: n.node.id })),
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
        mutation: campaignEditionOverviewFocus,
        variables: {
          id: this.props.campaign.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    campaignValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: campaignMutationFieldPatch,
          variables: { id: this.props.campaign.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { campaign } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], campaign),
      value: pathOr(null, ['createdByRef', 'node', 'id'], campaign),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], campaign),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: campaignMutationRelationAdd,
        variables: {
          id: this.props.campaign.id,
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
        mutation: campaignMutationRelationDelete,
        variables: {
          id: this.props.campaign.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      commitMutation({
        mutation: campaignMutationRelationAdd,
        variables: {
          id: this.props.campaign.id,
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

  handleChangeMarkingDefinition(name, values) {
    const { campaign } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(campaign);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: campaignMutationRelationAdd,
        variables: {
          id: this.props.campaign.id,
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
        mutation: campaignMutationRelationDelete,
        variables: {
          id: this.props.campaign.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const {
      t, campaign, editUsers, me,
    } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], campaign) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], campaign),
        value: pathOr(null, ['createdByRef', 'node', 'id'], campaign),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], campaign),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(campaign);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(campaign);
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
    )(campaign);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={campaignValidation(t)}
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

CampaignEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  campaign: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const CampaignEditionOverview = createFragmentContainer(
  CampaignEditionOverviewComponent,
  {
    campaign: graphql`
      fragment CampaignEditionOverview_campaign on Campaign {
        id
        name
        description
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
)(CampaignEditionOverview);
