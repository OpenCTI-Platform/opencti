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
import CreatedByField from '../form/CreatedByField';
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
  subscription StixDomainObjectEditionOverviewSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ...StixDomainObjectEditionOverview_stixDomainObject
    }
  }
`;

export const stixDomainObjectMutationFieldPatch = graphql`
  mutation StixDomainObjectEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixDomainObjectEditionOverview_stixDomainObject
      }
    }
  }
`;

export const stixDomainObjectEditionFocus = graphql`
  mutation StixDomainObjectEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixDomainObjectEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixDomainObjectMutationRelationAdd = graphql`
  mutation StixDomainObjectEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixDomainObjectEditionOverview_stixDomainObject
        }
      }
    }
  }
`;

const stixDomainObjectMutationRelationDelete = graphql`
  mutation StixDomainObjectEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationType: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationType: $relationType) {
        ...StixDomainObjectEditionOverview_stixDomainObject
      }
    }
  }
`;

const stixDomainObjectValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  aliases: Yup.string(),
  description: Yup.string(),
});

class StixDomainObjectEditionContainer extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: this.props.stixDomainObject.id,
      },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeCreatedBy(name, value) {
    const { stixDomainObject } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'node', 'name'], stixDomainObject),
      value: pathOr(null, ['createdBy', 'node', 'id'], stixDomainObject),
      relation: pathOr(null, ['createdBy', 'relation', 'id'], stixDomainObject),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationAdd,
        variables: {
          id: stixDomainObject.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationDelete,
        variables: {
          id: stixDomainObject.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixDomainObjectMutationRelationAdd,
          variables: {
            id: stixDomainObject.id,
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
    const { stixDomainObject } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixDomainObject);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationAdd,
        variables: {
          id: stixDomainObject.id,
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
        mutation: stixDomainObjectMutationRelationDelete,
        variables: {
          id: stixDomainObject.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: stixDomainObjectEditionFocus,
      variables: {
        id: this.props.stixDomainObject.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixDomainObjectValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixDomainObjectMutationFieldPatch,
          variables: {
            id: this.props.stixDomainObject.id,
            input: {
              key: name,
              value: name === 'aliases' ? split(',', value) : value,
            },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, classes, handleClose, stixDomainObject,
    } = this.props;
    const { editContext } = stixDomainObject;
    const createdBy = pathOr(null, ['createdBy', 'node', 'name'], stixDomainObject) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdBy', 'node', 'name'],
          stixDomainObject,
        ),
        value: pathOr(null, ['createdBy', 'node', 'id'], stixDomainObject),
        relation: pathOr(
          null,
          ['createdBy', 'relation', 'id'],
          stixDomainObject,
        ),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixDomainObject);
    const initialValues = pipe(
      assoc('aliases', join(',', stixDomainObject.aliases)),
      assoc('createdBy', createdBy),
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'aliases', 'description', 'createdBy', 'markingDefinitions']),
    )(stixDomainObject);
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
            validationSchema={stixDomainObjectValidation(t)}
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
                  name="aliases"
                  label={t('Aliases separated by commas')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="aliases"
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
                <CreatedByField
                  name="createdBy"
                  style={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="createdBy"
                    />
                  }
                  onChange={this.handleChangeCreatedBy.bind(this)}
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

StixDomainObjectEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainObjectEditionFragment = createFragmentContainer(
  StixDomainObjectEditionContainer,
  {
    stixDomainObject: graphql`
      fragment StixDomainObjectEditionOverview_stixDomainObject on StixDomainObject {
        id
        entity_type
        name
        description
        aliases
        createdBy {
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
)(StixDomainObjectEditionFragment);
