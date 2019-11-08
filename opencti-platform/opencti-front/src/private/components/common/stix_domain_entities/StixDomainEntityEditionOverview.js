import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import {
  compose,
  insert,
  find,
  propEq,
  pick,
  pipe,
  pathOr,
  map,
  assoc,
  difference,
  head,
  union,
  join,
  split,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  fetchQuery,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import Autocomplete from '../../../../components/Autocomplete';
import { markingDefinitionsSearchQuery } from '../../settings/MarkingDefinitions';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  button: {
    float: 'right',
    backgroundColor: '#f44336',
    borderColor: '#f44336',
    color: '#ffffff',
    '&:hover': {
      backgroundColor: '#c62828',
      borderColor: '#c62828',
    },
  },
});

const subscription = graphql`
  subscription StixDomainEntityEditionOverviewSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ...StixDomainEntityEditionOverview_stixDomainEntity
    }
  }
`;

export const stixDomainEntityMutationFieldPatch = graphql`
  mutation StixDomainEntityEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixDomainEntityEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixDomainEntityEditionOverview_stixDomainEntity
      }
    }
  }
`;

export const stixDomainEntityEditionFocus = graphql`
  mutation StixDomainEntityEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixDomainEntityEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixDomainEntityMutationRelationAdd = graphql`
  mutation StixDomainEntityEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    stixDomainEntityEdit(id: $id) {
      relationAdd(input: $input) {
        node {
          ...StixDomainEntityEditionOverview_stixDomainEntity
        }
      }
    }
  }
`;

const stixDomainEntityMutationRelationDelete = graphql`
  mutation StixDomainEntityEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    stixDomainEntityEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        node {
          ...StixDomainEntityEditionOverview_stixDomainEntity
        }
      }
    }
  }
`;

const stixDomainEntityValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  alias: Yup.string(),
  description: Yup.string(),
});

class StixDomainEntityEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { markingDefinitions: [] };
  }

  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: this.props.stixDomainEntity.id,
      },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
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

  handleChangeMarkingDefinition(name, values) {
    const { stixDomainEntity } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixDomainEntity);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixDomainEntityMutationRelationAdd,
        variables: {
          id: stixDomainEntity.id,
          input: {
            fromRole: 'so',
            toRole: 'marking',
            toId: head(added).value,
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: stixDomainEntityMutationRelationDelete,
        variables: {
          id: stixDomainEntity.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: stixDomainEntityEditionFocus,
      variables: {
        id: this.props.stixDomainEntity.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixDomainEntityValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixDomainEntityMutationFieldPatch,
          variables: {
            id: this.props.stixDomainEntity.id,
            input: {
              key: name,
              value: name === 'alias' ? split(',', value) : value,
            },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, stixDomainEntity, me,
    } = this.props;
    const { editContext } = stixDomainEntity;
    // Add current user to the context if is not available yet.
    const missingMe = find(propEq('name', me.email))(editContext) === undefined;
    const editUsers = missingMe
      ? insert(0, { name: me.email }, editContext)
      : editContext;
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixDomainEntity);
    const initialValues = pipe(
      assoc('alias', join(',', stixDomainEntity.alias)),
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'alias', 'description', 'markingDefinitions']),
    )(stixDomainEntity);
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an entity')}
          </Typography>
          <SubscriptionAvatars users={editUsers} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={stixDomainEntityValidation(t)}
            render={() => (
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
                      fieldName="last_seen"
                    />
                  }
                />
                <Field
                  name="alias"
                  component={TextField}
                  label={t('Aliases separated by commas')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="alias"
                    />
                  }
                />
                <Field
                  name="description"
                  component={TextField}
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
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
            )}
          />
        </div>
      </div>
    );
  }
}

StixDomainEntityEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixDomainEntity: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainEntityEditionFragment = createFragmentContainer(
  StixDomainEntityEditionContainer,
  {
    stixDomainEntity: graphql`
      fragment StixDomainEntityEditionOverview_stixDomainEntity on StixDomainEntity {
        id
        entity_type
        name
        description
        alias
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
        editContext {
          name
          focusOn
        }
      }
    `,
    me: graphql`
      fragment StixDomainEntityEditionOverview_me on User {
        email
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainEntityEditionFragment);
