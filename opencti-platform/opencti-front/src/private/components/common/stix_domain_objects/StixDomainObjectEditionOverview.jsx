import React, { useEffect } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { typesWithoutName } from '../../../../utils/hooks/useAttributes';
import CommitMessage from '../form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles((theme) => ({
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
}));

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
    $input: StixRefRelationshipAddInput!
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
  references: Yup.array(),
});

const StixDomainObjectEditionContainer = (props) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const { handleClose, stixDomainObject, noStoreUpdate } = props;

  const enableReferences = useIsEnforceReference(stixDomainObject.entity_type);

  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixDomainObject.id,
      },
    });
    return () => {
      sub.dispose();
    };
  });

  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: stixDomainObjectEditionFocus,
      variables: {
        id: stixDomainObject.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit = (values, { setSubmitting }) => {
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
        id: stixDomainObject.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      stixDomainObjectValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: stixDomainObjectMutationFieldPatch,
            variables: {
              id: stixDomainObject.id,
              input: {
                key: name,
                value:
                  name === 'aliases' || name === 'x_opencti_aliases'
                    ? R.split(',', value)
                    : value,
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: stixDomainObjectMutationFieldPatch,
        variables: {
          id: stixDomainObject.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(stixDomainObject);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: stixDomainObjectMutationRelationAdd,
          variables: {
            id: stixDomainObject.id,
            input: {
              toId: R.head(added).value,
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
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const { editContext } = stixDomainObject;
  const createdBy = R.pathOr(null, ['createdBy', 'name'], stixDomainObject) === null
    ? ''
    : {
      label: R.pathOr(null, ['createdBy', 'name'], stixDomainObject),
      value: R.pathOr(null, ['createdBy', 'id'], stixDomainObject),
    };
  const objectMarking = R.pipe(
    R.pathOr([], ['objectMarking', 'edges']),
    R.map((n) => ({
      label: n.node.definition,
      value: n.node.id,
    })),
  )(stixDomainObject);
  let initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.pick(['name', 'description', 'createdBy', 'objectMarking']),
  )(stixDomainObject);
  if ('aliases' in stixDomainObject) {
    initialValues = R.assoc(
      'aliases',
      stixDomainObject.aliases ? R.join(',', stixDomainObject.aliases) : '',
      initialValues,
    );
  }
  if ('x_opencti_aliases' in stixDomainObject) {
    initialValues = R.assoc(
      'x_opencti_aliases',
      stixDomainObject.x_opencti_aliases
        ? R.join(',', stixDomainObject.x_opencti_aliases)
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
          onClick={handleClose}
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
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
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
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
                  helperText={
                    <SubscriptionFocus context={editContext} fieldName="name" />
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
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
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
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
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
                  component={MarkdownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
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
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="createdBy"
                  />
                }
                onChange={handleChangeCreatedBy}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={fieldSpacingContainerStyle}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldname="objectMarking"
                  />
                }
                onChange={handleChangeObjectMarking}
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={values.references}
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
        ... on Grouping {
          name
          description
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
        ... on AdministrativeArea {
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
        ... on ThreatActorGroup {
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
              definition_type
              definition
              x_opencti_order
              x_opencti_color
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

export default StixDomainObjectEditionFragment;
