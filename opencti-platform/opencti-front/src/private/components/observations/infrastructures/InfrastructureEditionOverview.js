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

const infrastructureMutationFieldPatch = graphql`
  mutation InfrastructureEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    infrastructureEdit(id: $id) {
      fieldPatch(input: $input) {
        ...InfrastructureEditionOverview_infrastructure
        ...Infrastructure_infrastructure
      }
    }
  }
`;

export const infrastructureEditionOverviewFocus = graphql`
  mutation InfrastructureEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    infrastructureEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const infrastructureMutationRelationAdd = graphql`
  mutation InfrastructureEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    infrastructureEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...InfrastructureEditionOverview_infrastructure
        }
      }
    }
  }
`;

const infrastructureMutationRelationDelete = graphql`
  mutation InfrastructureEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    infrastructureEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...InfrastructureEditionOverview_infrastructure
      }
    }
  }
`;

const infrastructureValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class InfrastructureEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: infrastructureEditionOverviewFocus,
      variables: {
        id: this.props.infrastructure.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    infrastructureValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: infrastructureMutationFieldPatch,
          variables: {
            id: this.props.infrastructure.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: infrastructureMutationFieldPatch,
        variables: {
          id: this.props.infrastructure.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    const { infrastructure } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(infrastructure);
    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: infrastructureMutationRelationAdd,
        variables: {
          id: this.props.infrastructure.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: infrastructureMutationRelationDelete,
        variables: {
          id: this.props.infrastructure.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, infrastructure, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], infrastructure) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], infrastructure),
        value: pathOr(null, ['createdBy', 'id'], infrastructure),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(infrastructure);
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(infrastructure);
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
    )(infrastructure);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={infrastructureValidation(t)}
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

InfrastructureEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  infrastructure: PropTypes.object,
  context: PropTypes.array,
};

const InfrastructureEditionOverview = createFragmentContainer(
  InfrastructureEditionOverviewComponent,
  {
    infrastructure: graphql`
      fragment InfrastructureEditionOverview_infrastructure on Infrastructure {
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
)(InfrastructureEditionOverview);
