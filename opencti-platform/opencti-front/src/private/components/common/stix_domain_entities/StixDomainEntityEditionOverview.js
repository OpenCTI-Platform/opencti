import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc,
  difference,
  head,
  join,
  map,
  pathOr,
  pick,
  pipe,
  split,
  compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import CreatedByRefField from '../form/CreatedByRefField';
import MarkingDefinitionsField from '../form/MarkingDefinitionsField';

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
        from {
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
        ...StixDomainEntityEditionOverview_stixDomainEntity
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

  handleChangeCreatedByRef(name, value) {
    const { stixDomainEntity } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], stixDomainEntity),
      value: pathOr(null, ['createdByRef', 'node', 'id'], stixDomainEntity),
      relation: pathOr(
        null,
        ['createdByRef', 'relation', 'id'],
        stixDomainEntity,
      ),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: stixDomainEntityMutationRelationAdd,
        variables: {
          id: stixDomainEntity.id,
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
        mutation: stixDomainEntityMutationRelationDelete,
        variables: {
          id: stixDomainEntity.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixDomainEntityMutationRelationAdd,
          variables: {
            id: stixDomainEntity.id,
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
      t, classes, handleClose, stixDomainEntity,
    } = this.props;
    const { editContext } = stixDomainEntity;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], stixDomainEntity) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdByRef', 'node', 'name'],
          stixDomainEntity,
        ),
        value: pathOr(
          null,
          ['createdByRef', 'node', 'id'],
          stixDomainEntity,
        ),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          stixDomainEntity,
        ),
      };
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
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'alias',
        'description',
        'createdByRef',
        'markingDefinitions',
      ]),
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
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={stixDomainEntityValidation(t)}
          >
            {(setFieldValue) => (
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
                      context={editContext}
                      fieldName="last_seen"
                    />
                  }
                />
                <Field
                  component={TextField}
                  name="alias"
                  label={t('Aliases separated by commas')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="alias"
                    />
                  }
                />
                <Field
                  component={TextField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="description"
                    />
                  }
                />
                <CreatedByRefField
                  name="createdByRef"
                  style={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
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
                      context={editContext}
                      fieldName="markingDefinitions"
                    />
                  }
                  onChange={this.handleChangeMarkingDefinitions.bind(this)}
                />
              </Form>
            )}
          </Formik>
        </div>
      </div>
    );
  }
}

StixDomainEntityEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixDomainEntity: PropTypes.object,
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
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainEntityEditionFragment);
