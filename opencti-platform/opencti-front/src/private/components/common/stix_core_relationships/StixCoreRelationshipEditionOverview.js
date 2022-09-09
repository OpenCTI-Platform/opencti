import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import { buildDate, parse } from '../../../../utils/Time';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import MarkDownField from '../../../../components/MarkDownField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import SelectField from '../../../../components/SelectField';
import KillChainPhasesField from '../form/KillChainPhasesField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import CreatedByField from '../form/CreatedByField';
import ConfidenceField from '../form/ConfidenceField';
import CommitMessage from '../form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import StatusField from '../form/StatusField';
import DateTimePickerField from '../../../../components/DateTimePickerField';

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
  buttonLeft: {
    float: 'left',
  },
  buttonRight: {
    float: 'right',
    margin: '20px 0 0 10px',
  },
});

const subscription = graphql`
  subscription StixCoreRelationshipEditionOverviewSubscription($id: ID!) {
    stixCoreRelationship(id: $id) {
      ...StixCoreRelationshipEditionOverview_stixCoreRelationship
    }
  }
`;

const stixCoreRelationshipMutationFieldPatch = graphql`
  mutation StixCoreRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreRelationshipEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...StixCoreRelationshipEditionOverview_stixCoreRelationship
        ...StixCoreRelationshipOverview_stixCoreRelationship
      }
    }
  }
`;

export const stixCoreRelationshipEditionFocus = graphql`
  mutation StixCoreRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixCoreRelationshipMutationRelationAdd = graphql`
  mutation StixCoreRelationshipEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixCoreRelationshipEditionOverview_stixCoreRelationship
        }
      }
    }
  }
`;

const stixCoreRelationshipMutationRelationDelete = graphql`
  mutation StixCoreRelationshipEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixCoreRelationshipEditionOverview_stixCoreRelationship
      }
    }
  }
`;

const stixCoreRelationshipValidation = (t) => Yup.object().shape({
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  start_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  stop_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  description: Yup.string().nullable(),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

const StixCoreRelationshipEditionContainer = ({
  t,
  classes,
  handleClose,
  handleDelete,
  stixCoreRelationship,
  stixDomainObject,
  enableReferences,
  noStoreUpdate,
}) => {
  const { editContext } = stixCoreRelationship;
  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixCoreRelationship.id,
      },
    });
    return () => {
      sub.dispose();
    };
  });
  const handleChangeKillChainPhases = (name, values) => {
    if (!enableReferences) {
      const currentKillChainPhases = R.pipe(
        R.pathOr([], ['killChainPhases', 'edges']),
        R.map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(stixCoreRelationship);
      const added = R.difference(values, currentKillChainPhases);
      const removed = R.difference(currentKillChainPhases, values);
      if (added.length > 0) {
        commitMutation({
          mutation: stixCoreRelationshipMutationRelationAdd,
          variables: {
            id: stixCoreRelationship.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'kill-chain-phase',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: stixCoreRelationshipMutationRelationDelete,
          variables: {
            id: stixCoreRelationship.id,
            toId: R.head(removed).value,
            relationship_type: 'kill-chain-phase',
          },
        });
      }
    }
  };
  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentobjectMarking = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(stixCoreRelationship);
      const added = R.difference(values, currentobjectMarking);
      const removed = R.difference(currentobjectMarking, values);
      if (added.length > 0) {
        commitMutation({
          mutation: stixCoreRelationshipMutationRelationAdd,
          variables: {
            id: stixCoreRelationship.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: stixCoreRelationshipMutationRelationDelete,
          variables: {
            id: stixCoreRelationship.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: stixCoreRelationshipMutationFieldPatch,
        variables: {
          id: stixCoreRelationship.id,
          input: {
            key: 'createdBy',
            value: value.value || '',
          },
        },
      });
    }
  };
  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: stixCoreRelationshipEditionFocus,
      variables: {
        id: stixCoreRelationship.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      stixCoreRelationshipValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: stixCoreRelationshipMutationFieldPatch,
            variables: {
              id: stixCoreRelationship.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  };
  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('start_time', parse(values.start_time).format()),
      R.assoc('stop_time', parse(values.stop_time).format()),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    commitMutation({
      mutation: stixCoreRelationshipMutationFieldPatch,
      variables: {
        id: stixCoreRelationship.id,
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
  const createdBy = convertCreatedBy(stixCoreRelationship);
  const objectMarking = convertMarkings(stixCoreRelationship);
  const status = convertStatus(t, stixCoreRelationship);
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(stixCoreRelationship);
  const initialValues = R.pipe(
    R.assoc('start_time', buildDate(stixCoreRelationship.start_time)),
    R.assoc('stop_time', buildDate(stixCoreRelationship.stop_time)),
    R.assoc('createdBy', createdBy),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'confidence',
      'start_time',
      'stop_time',
      'description',
      'killChainPhases',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(stixCoreRelationship);
  const link = stixDomainObject
    ? resolveLink(stixDomainObject.entity_type)
    : '';
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
          {t('Update a relationship')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixCoreRelationshipValidation(t)}
          onSubmit={onSubmit}
        >
          {({
            submitForm,
            isSubmitting,
            validateForm,
            setFieldValue,
            values,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <ConfidenceField
                component={SelectField}
                variant="edit"
                name="confidence"
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                label={t('Confidence level')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
                editContext={editContext}
              />
              <Field
                component={DateTimePickerField}
                name="start_time"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                TextFieldProps={{
                  label: t('Start time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="start_time"
                    />
                  ),
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                TextFieldProps={{
                  label: t('Stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="stop_time"
                    />
                  ),
                }}
              />
              <Field
                component={MarkDownField}
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
              <KillChainPhasesField
                name="killChainPhases"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="killChainPhases"
                  />
                }
                onChange={handleChangeKillChainPhases}
              />
              {stixCoreRelationship.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="stix-core-relationship"
                  onFocus={handleChangeFocus}
                  onChange={handleSubmitField}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_workflow_id"
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
                onChange={handleChangeCreatedBy}
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
                onChange={handleChangeObjectMarking}
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  validateForm={validateForm}
                  setFieldValue={setFieldValue}
                  values={values}
                  id={stixCoreRelationship.id}
                  noStoreUpdate={noStoreUpdate}
                />
              )}
            </Form>
          )}
        </Formik>
        {stixDomainObject && (
          <Button
            variant="contained"
            color="primary"
            component={Link}
            to={`${link}/${stixDomainObject.id}/knowledge/relations/${stixCoreRelationship.id}`}
            classes={{ root: classes.buttonLeft }}
          >
            {t('Details')}
          </Button>
        )}
        {typeof handleDelete === 'function' && (
          <Button
            variant="contained"
            onClick={() => handleDelete()}
            classes={{ root: classes.button }}
          >
            {t('Delete')}
          </Button>
        )}
      </div>
    </div>
  );
};

StixCoreRelationshipEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  stixCoreRelationship: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  noStoreUpdate: PropTypes.bool,
};

const StixCoreRelationshipEditionFragment = createFragmentContainer(
  StixCoreRelationshipEditionContainer,
  {
    stixCoreRelationship: graphql`
      fragment StixCoreRelationshipEditionOverview_stixCoreRelationship on StixCoreRelationship {
        id
        confidence
        start_time
        stop_time
        description
        relationship_type
        is_inferred
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              x_opencti_order
            }
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

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixCoreRelationshipEditionFragment);
