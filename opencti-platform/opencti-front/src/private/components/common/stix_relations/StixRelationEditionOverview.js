import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import {
  ascend, assoc, compose, difference, head, map, path, pathOr, pick, pipe, sortWith, union,
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
  commitMutation, fetchQuery, QueryRenderer, requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../../components/Subscription';
import Select from '../../../../components/Select';
import Autocomplete from '../../../../components/Autocomplete';
import DatePickerField from '../../../../components/DatePickerField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import { killChainPhasesSearchQuery } from '../../settings/KillChainPhases';
import Loader from '../../../../components/Loader';

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
  const [killChains, setKillChains] = useState([]);
  const [markingDefs, setMarkingDefs] = useState([]);
  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixRelation.id,
      },
    });
    return () => { sub.dispose(); };
  });

  const searchKillChainPhases = (event) => {
    fetchQuery(killChainPhasesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const killChainPhases = pipe(
        pathOr([], ['killChainPhases', 'edges']),
        sortWith([ascend(path(['node', 'phase_order']))]),
        map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(data);
      setKillChains(union(killChains, killChainPhases));
    });
  };
  const searchMarkingDefinitions = (event) => {
    fetchQuery(markingDefinitionsLinesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map((n) => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      setMarkingDefs(union(markingDefs, markingDefinitions));
    });
  };
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
  const handleChangeMarkingDefinition = (name, values) => {
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
    assoc('killChainPhases', killChainPhases),
    assoc('markingDefinitions', markingDefinitions),
    pick([
      'weight',
      'first_seen',
      'last_seen',
      'description',
      'role_played',
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
          <IconButton aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}>
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a relationship')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <QueryRenderer query={attributesQuery}
            variables={{ type: 'role_played' }}
            render={({ props }) => {
              if (props && props.attributes) {
                const rolesPlayedEdges = props.attributes.edges;
                return (
                  <Formik
                    enableReinitialize={true}
                    initialValues={initialValues}
                    validationSchema={stixRelationValidation(t)}
                    render={() => (
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          name="weight"
                          component={Select}
                          onFocus={handleChangeFocus}
                          onChange={handleSubmitField}
                          label={t('Confidence level')}
                          fullWidth={true}
                          inputProps={{
                            name: 'weight',
                            id: 'weight',
                          }}
                          containerstyle={{ width: '100%' }}
                          helpertext={
                            <SubscriptionFocus context={editContext} fieldName="weight"/>
                          }>
                          <MenuItem value="1">{t('Low')}</MenuItem>
                          <MenuItem value="2">{t('Moderate')}</MenuItem>
                          <MenuItem value="3">{t('Good')}</MenuItem>
                          <MenuItem value="4">{t('Strong')}</MenuItem>
                        </Field>
                        {stixRelation.relationship_type === 'indicates' ? (
                          <Field
                            name="role_played"
                            component={Select}
                            onFocus={handleChangeFocus}
                            onChange={handleSubmitField}
                            label={t('Played role')}
                            fullWidth={true}
                            inputProps={{
                              name: 'role_played',
                              id: 'role_played',
                            }}
                            containerstyle={{ marginTop: 10, width: '100%' }}
                            helpertext={
                              <SubscriptionFocus context={editContext} fieldName="role_played"/>
                            }>
                            {rolesPlayedEdges.map((rolePlayedEdge) => (
                              <MenuItem
                                key={rolePlayedEdge.node.value}
                                value={rolePlayedEdge.node.value}>
                                {t(rolePlayedEdge.node.value)}
                              </MenuItem>
                            ))}
                          </Field>
                        ) : (
                          ''
                        )}
                        <Field
                          name="first_seen"
                          component={DatePickerField}
                          label={t('First seen')}
                          fullWidth={true}
                          style={{ marginTop: 10 }}
                          onFocus={handleChangeFocus}
                          onSubmit={handleSubmitField}
                          helperText={
                            <SubscriptionFocus context={editContext} fieldName="first_seen"/>
                          }
                        />
                        <Field
                          name="last_seen"
                          component={DatePickerField}
                          label={t('Last seen')}
                          fullWidth={true}
                          style={{ marginTop: 10 }}
                          onFocus={handleChangeFocus}
                          onSubmit={handleSubmitField}
                          helperText={
                            <SubscriptionFocus context={editContext} fieldName="last_seen"/>
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
                          onFocus={handleChangeFocus}
                          onSubmit={handleSubmitField}
                          helperText={
                            <SubscriptionFocus context={editContext} fieldName="description"/>
                          }
                        />
                        <Field
                          name="killChainPhases"
                          component={Autocomplete}
                          multiple={true}
                          label={t('Kill chain phases')}
                          options={killChains}
                          onInputChange={searchKillChainPhases}
                          onChange={handleChangeKillChainPhases}
                          onFocus={handleChangeFocus}
                          helperText={
                            <SubscriptionFocus context={editContext} fieldName="killChainPhases"/>
                          }
                        />
                        <Field
                          name="markingDefinitions"
                          component={Autocomplete}
                          multiple={true}
                          label={t('Marking')}
                          options={markingDefs}
                          onInputChange={searchMarkingDefinitions}
                          onChange={handleChangeMarkingDefinition}
                          onFocus={handleChangeFocus}
                          helperText={
                            <SubscriptionFocus context={editContext} fieldName="markingDefinitions"/>
                          }
                        />
                      </Form>
                    )}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
          {stixDomainEntity ? (
            <Button variant="contained"
              color="primary"
              component={Link}
              to={`${link}/${stixDomainEntity.id}/knowledge/relations/${stixRelation.id}`}
              classes={{ root: classes.buttonLeft }}>
              {t('Details')}
            </Button>
          ) : (
            ''
          )}
          {typeof handleDelete === 'function' ? (
            <Button variant="contained"
              onClick={handleDelete.bind(this)}
              classes={{ root: classes.button }}>
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
