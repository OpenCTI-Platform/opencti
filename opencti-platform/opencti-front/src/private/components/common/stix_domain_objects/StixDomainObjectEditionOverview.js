import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
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
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
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
import { typesWithoutName } from '../../../../utils/Entity';
import CommitMessage from '../form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
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
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
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
    $toId: StixRef!
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
  description: Yup.string().nullable(),
  aliases: Yup.string().nullable(),
  x_opencti_aliases: Yup.string().nullable(),
  references: Yup.array().required(t('This field is required')),
});

class StixDomainObjectEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.stixDomainObject.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
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

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.status_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: stixDomainObjectMutationFieldPatch,
      variables: {
        id: this.props.stixDomainObject.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
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
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: stixDomainObjectMutationFieldPatch,
        variables: {
          id: this.props.stixDomainObject.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
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
  }

  render() {
    const {
      t,
      classes,
      handleClose,
      stixDomainObject,
      noStoreUpdate,
      enableReferences,
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
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
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
            onSubmit={this.onSubmit.bind(this)}
          >
            {({
              submitForm,
              isSubmitting,
              validateForm,
              setFieldValue,
              values,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                {'name' in stixDomainObject && (
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    disabled={typesWithoutName.includes(
                      stixDomainObject.entity_type,
                    )}
                    onFocus={this.handleChangeFocus.bind(this)}
                    onSubmit={this.handleSubmitField.bind(this)}
                    helperText={
                      <SubscriptionFocus
                        context={editContext}
                        fieldName="name"
                      />
                    }
                  />
                )}
                {'aliases' in stixDomainObject && (
                  <Field
                    component={TextField}
                    variant="standard"
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
                )}
                {'x_opencti_aliases' in stixDomainObject && (
                  <Field
                    component={TextField}
                    variant="standard"
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
                )}
                {'description' in stixDomainObject && (
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
                )}
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
                {enableReferences && (
                  <CommitMessage
                    submitForm={submitForm}
                    disabled={isSubmitting}
                    validateForm={validateForm}
                    setFieldValue={setFieldValue}
                    values={values}
                    id={stixDomainObject.id}
                    noStoreUpdate={noStoreUpdate}
                  />
                )}
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
  noStoreUpdate: PropTypes.bool,
  enableReferences: PropTypes.bool,
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
        ... on ObservedData {
          name
        }
        ... on Report {
          name
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
        ... on System {
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
