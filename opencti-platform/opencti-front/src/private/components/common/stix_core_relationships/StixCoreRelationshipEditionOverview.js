import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc,
  compose,
  difference,
  head,
  map,
  pathOr,
  pick,
  pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import { dateFormat } from '../../../../utils/Time';
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
import DatePickerField from '../../../../components/DatePickerField';
import KillChainPhasesField from '../form/KillChainPhasesField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import CreatedByField from '../form/CreatedByField';
import ConfidenceField from '../form/ConfidenceField';

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
  buttonLeft: {
    float: 'left',
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
    $input: EditInput!
  ) {
    stixCoreRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
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
    $toId: String!
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
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  stop_time: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  description: Yup.string(),
});

const StixCoreRelationshipEditionContainer = ({
  t,
  classes,
  handleClose,
  handleDelete,
  stixCoreRelationship,
  stixDomainObject,
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
    const currentKillChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(stixCoreRelationship);

    const added = difference(values, currentKillChainPhases);
    const removed = difference(currentKillChainPhases, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixCoreRelationshipMutationRelationAdd,
        variables: {
          id: stixCoreRelationship.id,
          input: {
            toId: head(added).value,
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
          toId: head(removed).value,
          relationship_type: 'kill-chain-phase',
        },
      });
    }
  };
  const handleChangeobjectMarking = (name, values) => {
    const currentobjectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(stixCoreRelationship);

    const added = difference(values, currentobjectMarking);
    const removed = difference(currentobjectMarking, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixCoreRelationshipMutationRelationAdd,
        variables: {
          id: stixCoreRelationship.id,
          input: {
            toId: head(added).value,
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
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], stixCoreRelationship),
      value: pathOr(null, ['createdBy', 'id'], stixCoreRelationship),
    };
    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: stixCoreRelationshipMutationRelationAdd,
        variables: {
          id: stixCoreRelationship.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: stixCoreRelationshipMutationRelationDelete,
        variables: {
          id: stixCoreRelationship.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixCoreRelationshipMutationRelationAdd,
          variables: {
            id: stixCoreRelationship.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
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
    stixCoreRelationshipValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixCoreRelationshipMutationFieldPatch,
          variables: {
            id: stixCoreRelationship.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };
  const createdBy = pathOr(null, ['createdBy', 'name'], stixCoreRelationship) === null
    ? ''
    : {
      label: pathOr(null, ['createdBy', 'name'], stixCoreRelationship),
      value: pathOr(null, ['createdBy', 'id'], stixCoreRelationship),
    };
  const killChainPhases = pipe(
    pathOr([], ['killChainPhases', 'edges']),
    map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(stixCoreRelationship);
  const objectMarking = pipe(
    pathOr([], ['objectMarking', 'edges']),
    map((n) => ({
      label: n.node.definition,
      value: n.node.id,
    })),
  )(stixCoreRelationship);
  const initialValues = pipe(
    assoc('start_time', dateFormat(stixCoreRelationship.start_time)),
    assoc('stop_time', dateFormat(stixCoreRelationship.stop_time)),
    assoc('createdBy', createdBy),
    assoc('killChainPhases', killChainPhases),
    assoc('objectMarking', objectMarking),
    pick([
      'confidence',
      'start_time',
      'stop_time',
      'description',
      'killChainPhases',
      'createdBy',
      'objectMarking',
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
        >
          <Close fontSize="small" />
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
        >
          {({ setFieldValue }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <ConfidenceField
                component={SelectField}
                name="confidence"
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                label={t('Confidence level')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
                editContext={editContext}
                variant="edit"
              />
              <Field
                component={DatePickerField}
                name="start_time"
                label={t('Start time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="start_time"
                  />
                }
              />
              <Field
                component={DatePickerField}
                name="stop_time"
                label={t('Stop time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="stop_time"
                  />
                }
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
                onChange={handleChangeobjectMarking}
              />
            </Form>
          )}
        </Formik>
        {stixDomainObject ? (
          <Button
            variant="contained"
            color="primary"
            component={Link}
            to={`${link}/${stixDomainObject.id}/knowledge/relations/${stixCoreRelationship.id}`}
            classes={{ root: classes.buttonLeft }}
          >
            {t('Details')}
          </Button>
        ) : (
          ''
        )}
        {typeof handleDelete === 'function' ? (
          <Button
            variant="contained"
            onClick={() => handleDelete()}
            classes={{ root: classes.button }}
          >
            {t('Delete')}
          </Button>
        ) : (
          ''
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

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixCoreRelationshipEditionFragment);
