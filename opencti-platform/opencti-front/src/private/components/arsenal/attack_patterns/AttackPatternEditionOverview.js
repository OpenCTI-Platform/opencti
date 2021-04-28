import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
  difference,
  head,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AttackPatternEditionOverview_attackPattern
        ...AttackPattern_attackPattern
      }
    }
  }
`;

export const attackPatternEditionOverviewFocus = graphql`
  mutation AttackPatternEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const attackPatternMutationRelationAdd = graphql`
  mutation AttackPatternEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    attackPatternEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...AttackPatternEditionOverview_attackPattern
        }
      }
    }
  }
`;

const attackPatternMutationRelationDelete = graphql`
  mutation AttackPatternEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    attackPatternEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...AttackPatternEditionOverview_attackPattern
      }
    }
  }
`;

const attackPatternValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class AttackPatternEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: attackPatternEditionOverviewFocus,
      variables: {
        id: this.props.attackPattern.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    attackPatternValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: attackPatternMutationFieldPatch,
          variables: {
            id: this.props.attackPattern.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { attackPattern } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], attackPattern),
      value: pathOr(null, ['createdBy', 'id'], attackPattern),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: attackPatternMutationRelationAdd,
          variables: {
            id: this.props.attackPattern.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
    }
  }

  handleChangeKillChainPhases(name, values) {
    const { attackPattern } = this.props;
    const currentKillChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(attackPattern);

    const added = difference(values, currentKillChainPhases);
    const removed = difference(currentKillChainPhases, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            toId: head(added).value,
            relationship_type: 'kill-chain-phase',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          toId: head(removed).value,
          relationship_type: 'kill-chain-phase',
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    const { attackPattern } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(attackPattern);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, attackPattern, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], attackPattern) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], attackPattern),
        value: pathOr(null, ['createdBy', 'id'], attackPattern),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(attackPattern);
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(attackPattern);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('killChainPhases', killChainPhases),
      assoc('objectMarking', objectMarking),
      pick([
        'name',
        'description',
        'createdBy',
        'killChainPhases',
        'objectMarking',
      ]),
    )(attackPattern);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={attackPatternValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <KillChainPhasesField
              name="killChainPhases"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="killChainPhases"
                />
              }
              onChange={this.handleChangeKillChainPhases.bind(this)}
            />
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

AttackPatternEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  attackPattern: PropTypes.object,
  context: PropTypes.array,
};

const AttackPatternEditionOverview = createFragmentContainer(
  AttackPatternEditionOverviewComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionOverview_attackPattern on AttackPattern {
        id
        name
        description
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
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(AttackPatternEditionOverview);
