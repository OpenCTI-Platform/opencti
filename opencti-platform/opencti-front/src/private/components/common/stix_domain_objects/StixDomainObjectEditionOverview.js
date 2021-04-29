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
import MarkDownField from '../../../../components/MarkDownField';
import inject18n from '../../../../components/i18n';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';

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
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixDomainObjectEditionOverview_stixDomainObject
      }
    }
  }
`;

const stixDomainObjectValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  aliases: Yup.string(),
  x_opencti_aliases: Yup.string(),
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
      label: pathOr(null, ['createdBy', 'name'], stixDomainObject),
      value: pathOr(null, ['createdBy', 'id'], stixDomainObject),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationAdd,
        variables: {
          id: stixDomainObject.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationDelete,
        variables: {
          id: stixDomainObject.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixDomainObjectMutationRelationAdd,
          variables: {
            id: stixDomainObject.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
    }
  }

  handleChangeObjectMarking(name, values) {
    const { stixDomainObject } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
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
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: stixDomainObjectMutationRelationDelete,
        variables: {
          id: stixDomainObject.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
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
              value:
                name === 'aliases' || name === 'x_opencti_aliases'
                  ? split(',', value)
                  : value,
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
    const createdBy = pathOr(null, ['createdBy', 'name'], stixDomainObject) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], stixDomainObject),
        value: pathOr(null, ['createdBy', 'id'], stixDomainObject),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(stixDomainObject);
    let initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      pick(['name', 'description', 'createdBy', 'objectMarking']),
    )(stixDomainObject);
    if ('aliases' in stixDomainObject) {
      initialValues = assoc(
        'aliases',
        stixDomainObject.aliases ? join(',', stixDomainObject.aliases) : '',
        initialValues,
      );
    }
    if ('x_opencti_aliases' in stixDomainObject) {
      initialValues = assoc(
        'x_opencti_aliases',
        stixDomainObject.x_opencti_aliases
          ? join(',', stixDomainObject.x_opencti_aliases)
          : '',
        initialValues,
      );
    }
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
                {'aliases' in stixDomainObject ? (
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
                ) : (
                  ''
                )}
                {'x_opencti_aliases' in stixDomainObject ? (
                  <Field
                    component={TextField}
                    name="x_opencti_aliases"
                    label={t('Aliases separated by commas')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onFocus={this.handleChangeFocus.bind(this)}
                    onSubmit={this.handleSubmitField.bind(this)}
                    helperText={
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="x_opencti_aliases"
                      />
                    }
                  />
                ) : (
                  ''
                )}
                <Field
                  component={MarkDownField}
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
                <ObjectMarkingField
                  name="objectMarking"
                  style={{ marginTop: 20, width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
                      fieldname="objectMarking"
                    />
                  }
                  onChange={this.handleChangeObjectMarking.bind(this)}
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
        parent_types
        ... on AttackPattern {
          name
          description
          aliases
        }
        ... on Campaign {
          name
          description
          aliases
        }
        ... on CourseOfAction {
          name
          description
          x_opencti_aliases
        }
        ... on Individual {
          name
          description
          x_opencti_aliases
        }
        ... on Organization {
          name
          description
          x_opencti_aliases
        }
        ... on Sector {
          name
          description
          x_opencti_aliases
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
          aliases
        }
        ... on Position {
          name
          description
          x_opencti_aliases
        }
        ... on City {
          name
          description
          x_opencti_aliases
        }
        ... on Country {
          name
          description
          x_opencti_aliases
        }
        ... on Region {
          name
          description
          x_opencti_aliases
        }
        ... on Malware {
          name
          description
          aliases
        }
        ... on ThreatActor {
          name
          description
          aliases
        }
        ... on Tool {
          name
          description
          aliases
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
          aliases
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
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
