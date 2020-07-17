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
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import DatePickerField from '../../../../components/DatePickerField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import MarkingDefinitionsField from '../form/MarkingDefinitionsField';
import CreatedByField from '../form/CreatedByField';
import ConfidenceField from '../form/ConfidenceField';
import SwitchField from '../../../../components/SwitchField';

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
  subscription StixSightingEditionOverviewSubscription($id: ID!) {
    stixSighting(id: $id) {
      ...StixSightingEditionOverview_stixSighting
    }
  }
`;

const stixSightingMutationFieldPatch = graphql`
  mutation StixSightingEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixSightingEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixSightingEditionOverview_stixSighting
      }
    }
  }
`;

export const stixSightingEditionFocus = graphql`
  mutation StixSightingEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixSightingEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixSightingMutationRelationAdd = graphql`
  mutation StixSightingEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    stixSightingEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixSightingEditionOverview_stixSighting
        }
      }
    }
  }
`;

const stixSightingMutationRelationDelete = graphql`
  mutation StixSightingEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    stixSightingEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...StixSightingEditionOverview_stixSighting
      }
    }
  }
`;

const stixSightingValidation = (t) => Yup.object().shape({
  number: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  confidence: Yup.number()
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
  negative: Yup.boolean(),
});

const StixSightingEditionContainer = ({
  t,
  classes,
  handleClose,
  handleDelete,
  stixSighting,
  stixDomainObject,
}) => {
  const { editContext } = stixSighting;
  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixSighting.id,
      },
    });
    return () => {
      sub.dispose();
    };
  });
  const handleChangeMarkingDefinitions = (name, values) => {
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixSighting);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixSightingMutationRelationAdd,
        variables: {
          id: stixSighting.id,
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
        mutation: stixSightingMutationRelationDelete,
        variables: {
          id: stixSighting.id,
          relationId: head(removed).relationId,
        },
      });
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'node', 'name'], stixSighting),
      value: pathOr(null, ['createdBy', 'node', 'id'], stixSighting),
      relation: pathOr(null, ['createdBy', 'relation', 'id'], stixSighting),
    };
    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: stixSightingMutationRelationAdd,
        variables: {
          id: stixSighting.id,
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
        mutation: stixSightingMutationRelationDelete,
        variables: {
          id: stixSighting.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixSightingMutationRelationAdd,
          variables: {
            id: stixSighting.id,
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
      mutation: stixSightingEditionFocus,
      variables: {
        id: stixSighting.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name, value) => {
    stixSightingValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixSightingMutationFieldPatch,
          variables: {
            id: stixSighting.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };
  const createdBy = pathOr(null, ['createdBy', 'node', 'name'], stixSighting) === null
    ? ''
    : {
      label: pathOr(null, ['createdBy', 'node', 'name'], stixSighting),
      value: pathOr(null, ['createdBy', 'node', 'id'], stixSighting),
      relation: pathOr(
        null,
        ['createdBy', 'relation', 'id'],
        stixSighting,
      ),
    };
  const markingDefinitions = pipe(
    pathOr([], ['markingDefinitions', 'edges']),
    map((n) => ({
      label: n.node.definition,
      value: n.node.id,
      relationId: n.relation.id,
    })),
  )(stixSighting);
  const initialValues = pipe(
    assoc('first_seen', dateFormat(stixSighting.first_seen)),
    assoc('last_seen', dateFormat(stixSighting.last_seen)),
    assoc('createdBy', createdBy),
    assoc('markingDefinitions', markingDefinitions),
    pick([
      'number',
      'confidence',
      'first_seen',
      'last_seen',
      'description',
      'negative',
      'createdBy',
      'markingDefinitions',
    ]),
  )(stixSighting);
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
          {t('Update a sighting')}
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
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={stixSightingValidation(t)}
                >
                  {(setFieldValue) => (
                    <Form style={{ margin: '20px 0 20px 0' }}>
                      <Field
                        component={TextField}
                        name="number"
                        label={t('Count')}
                        fullWidth={true}
                        onFocus={handleChangeFocus}
                        onSubmit={handleSubmitField}
                        helperText={
                          <SubscriptionFocus
                            context={editContext}
                            fieldName="number"
                          />
                        }
                      />
                      <ConfidenceField
                        variant="edit"
                        name="confidence"
                        label={t('Confidence level')}
                        onFocus={handleChangeFocus}
                        onChange={handleSubmitField}
                        editContext={editContext}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                      />
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
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="negative"
                        label={t(
                          'Sighed a false positive (negative feedback)?',
                        )}
                        containerstyle={{ marginTop: 20 }}
                        onChange={handleSubmitField}
                        helperText={
                          <SubscriptionFocus
                            context={editContext}
                            fieldName="negative"
                          />
                        }
                      />
                    </Form>
                  )}
                </Formik>
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
        {stixDomainObject ? (
          <Button
            variant="contained"
            color="primary"
            component={Link}
            to={`${link}/${stixDomainObject.id}/knowledge/relations/${stixSighting.id}`}
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

StixSightingEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  stixSighting: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const StixSightingEditionFragment = createFragmentContainer(
  StixSightingEditionContainer,
  {
    stixSighting: graphql`
      fragment StixSightingEditionOverview_stixSighting on StixSighting {
        id
        number
        negative
        confidence
        first_seen
        last_seen
        description
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
)(StixSightingEditionFragment);
