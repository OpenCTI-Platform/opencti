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
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import { Close } from '@material-ui/icons';
import * as Yup from 'yup';
import { dateFormat } from '../../../../utils/Time';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import SelectField from '../../../../components/SelectField';
import DatePickerField from '../../../../components/DatePickerField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import KillChainPhasesField from '../form/KillChainPhasesField';
import MarkingDefinitionsField from '../form/MarkingDefinitionsField';
import CreatedByRefField from '../form/CreatedByRefField';

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
  subscription StixRelationEditionOverviewSubscription($id: ID!) {
    stixRelation(id: $id) {
      ...StixRelationEditionOverview_stixRelation
    }
  }
`;

const stixRelationMutationFieldPatch = graphql`
  mutation StixRelationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixRelationEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixRelationEditionOverview_stixRelation
      }
    }
  }
`;

export const stixRelationEditionFocus = graphql`
  mutation StixRelationEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixRelationEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixRelationMutationRelationAdd = graphql`
  mutation StixRelationEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    stixRelationEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixRelationEditionOverview_stixRelation
        }
      }
    }
  }
`;

const stixRelationMutationRelationDelete = graphql`
  mutation StixRelationEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    stixRelationEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...StixRelationEditionOverview_stixRelation
      }
    }
  }
`;

const stixRelationValidation = (t) => Yup.object().shape({
  weight: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  description: Yup.string(),
  role_played: Yup.string(),
});

const StixRelationEditionContainer = ({
  t,
  classes,
  handleClose,
  handleDelete,
  stixRelation,
  stixDomainEntity,
}) => {
  const { editContext } = stixRelation;
  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixRelation.id,
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
        relationId: n.relation.id,
      })),
    )(stixRelation);

    const added = difference(values, currentKillChainPhases);
    const removed = difference(currentKillChainPhases, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixRelationMutationRelationAdd,
        variables: {
          id: stixRelation.id,
          input: {
            fromRole: 'phase_belonging',
            toId: head(added).value,
            toRole: 'kill_chain_phase',
            through: 'kill_chain_phases',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: stixRelationMutationRelationDelete,
        variables: {
          id: stixRelation.id,
          relationId: head(removed).relationId,
        },
      });
    }
  };
  const handleChangeMarkingDefinitions = (name, values) => {
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixRelation);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixRelationMutationRelationAdd,
        variables: {
          id: stixRelation.id,
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
        mutation: stixRelationMutationRelationDelete,
        variables: {
          id: stixRelation.id,
          relationId: head(removed).relationId,
        },
      });
    }
  };
  const handleChangeCreatedByRef = (name, value) => {
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], stixRelation),
      value: pathOr(null, ['createdByRef', 'node', 'id'], stixRelation),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], stixRelation),
    };
    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: stixRelationMutationRelationAdd,
        variables: {
          id: stixRelation.id,
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
        mutation: stixRelationMutationRelationDelete,
        variables: {
          id: stixRelation.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixRelationMutationRelationAdd,
          variables: {
            id: stixRelation.id,
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
  };
  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: stixRelationEditionFocus,
      variables: {
        id: stixRelation.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name, value) => {
    stixRelationValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixRelationMutationFieldPatch,
          variables: {
            id: stixRelation.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };
  const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], stixRelation) === null
    ? ''
    : {
      label: pathOr(null, ['createdByRef', 'node', 'name'], stixRelation),
      value: pathOr(null, ['createdByRef', 'node', 'id'], stixRelation),
      relation: pathOr(
        null,
        ['createdByRef', 'relation', 'id'],
        stixRelation,
      ),
    };
  const killChainPhases = pipe(
    pathOr([], ['killChainPhases', 'edges']),
    map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
      relationId: n.relation.id,
    })),
  )(stixRelation);
  const markingDefinitions = pipe(
    pathOr([], ['markingDefinitions', 'edges']),
    map((n) => ({
      label: n.node.definition,
      value: n.node.id,
      relationId: n.relation.id,
    })),
  )(stixRelation);
  const initialValues = pipe(
    assoc('first_seen', dateFormat(stixRelation.first_seen)),
    assoc('last_seen', dateFormat(stixRelation.last_seen)),
    assoc('createdByRef', createdByRef),
    assoc('killChainPhases', killChainPhases),
    assoc('markingDefinitions', markingDefinitions),
    pick([
      'weight',
      'first_seen',
      'last_seen',
      'description',
      'role_played',
      'createdByRef',
      'killChainPhases',
      'markingDefinitions',
    ]),
  )(stixRelation);
  const link = stixDomainEntity
    ? resolveLink(stixDomainEntity.entity_type)
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
        <QueryRenderer
          query={attributesQuery}
          variables={{ type: 'role_played' }}
          render={({ props }) => {
            if (props && props.attributes) {
              const rolesPlayedEdges = props.attributes.edges;
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={stixRelationValidation(t)}
                >
                  {(setFieldValue) => (
                    <Form style={{ margin: '20px 0 20px 0' }}>
                      <Field
                        component={SelectField}
                        name="weight"
                        onFocus={handleChangeFocus}
                        onChange={handleSubmitField}
                        label={t('Confidence level')}
                        fullWidth={true}
                        containerstyle={{ width: '100%' }}
                        helpertext={
                          <SubscriptionFocus
                            context={editContext}
                            fieldName="weight"
                          />
                        }
                      >
                        <MenuItem value="1">{t('Low')}</MenuItem>
                        <MenuItem value="2">{t('Moderate')}</MenuItem>
                        <MenuItem value="3">{t('Good')}</MenuItem>
                        <MenuItem value="4">{t('Strong')}</MenuItem>
                      </Field>
                      {stixRelation.relationship_type === 'indicates' ? (
                        <Field
                          component={SelectField}
                          name="role_played"
                          onFocus={handleChangeFocus}
                          onChange={handleSubmitField}
                          label={t('Played role')}
                          fullWidth={true}
                          containerstyle={{ marginTop: 20, width: '100%' }}
                          helpertext={
                            <SubscriptionFocus
                              context={editContext}
                              fieldName="role_played"
                            />
                          }
                        >
                          {rolesPlayedEdges.map((rolePlayedEdge) => (
                            <MenuItem
                              key={rolePlayedEdge.node.value}
                              value={rolePlayedEdge.node.value}
                            >
                              {t(rolePlayedEdge.node.value)}
                            </MenuItem>
                          ))}
                        </Field>
                      ) : (
                        ''
                      )}
                      <Field
                        component={DatePickerField}
                        name="first_seen"
                        label={t('First seen')}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                        onFocus={handleChangeFocus}
                        onSubmit={handleSubmitField}
                        helperText={
                          <SubscriptionFocus
                            context={editContext}
                            fieldName="first_seen"
                          />
                        }
                      />
                      <Field
                        component={DatePickerField}
                        name="last_seen"
                        label={t('Last seen')}
                        invalidDateMessage={t(
                          'The value must be a date (YYYY-MM-DD)',
                        )}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                        onFocus={handleChangeFocus}
                        onSubmit={handleSubmitField}
                        helperText={
                          <SubscriptionFocus
                            context={editContext}
                            fieldName="last_seen"
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
                        onChange={handleChangeCreatedByRef}
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
                        onChange={handleChangeMarkingDefinitions}
                      />
                    </Form>
                  )}
                </Formik>
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
        {stixDomainEntity ? (
          <Button
            variant="contained"
            color="primary"
            component={Link}
            to={`${link}/${stixDomainEntity.id}/knowledge/relations/${stixRelation.id}`}
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

StixRelationEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainEntity: PropTypes.object,
  stixRelation: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixRelationEditionFragment = createFragmentContainer(
  StixRelationEditionContainer,
  {
    stixRelation: graphql`
      fragment StixRelationEditionOverview_stixRelation on StixRelation {
        id
        weight
        first_seen
        last_seen
        description
        relationship_type
        role_played
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
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              phase_order
            }
            relation {
              id
            }
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
)(StixRelationEditionFragment);
