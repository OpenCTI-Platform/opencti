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

const IncidentMutationFieldPatch = graphql`
  mutation IncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    incidentEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

export const IncidentEditionOverviewFocus = graphql`
  mutation IncidentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const IncidentMutationRelationAdd = graphql`
  mutation IncidentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    incidentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IncidentEditionOverview_incident
        }
      }
    }
  }
`;

const IncidentMutationRelationDelete = graphql`
  mutation IncidentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    incidentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const IncidentValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class IncidentEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: IncidentEditionOverviewFocus,
      variables: {
        id: this.props.incident.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    IncidentValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: IncidentMutationFieldPatch,
          variables: {
            id: this.props.incident.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { Incident } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], Incident),
      value: pathOr(null, ['createdBy', 'id'], Incident),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: IncidentMutationRelationAdd,
        variables: {
          id: this.props.incident.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: IncidentMutationRelationDelete,
        variables: {
          id: this.props.incident.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: IncidentMutationRelationAdd,
          variables: {
            id: this.props.incident.id,
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
    const { Incident } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(Incident);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: IncidentMutationRelationAdd,
        variables: {
          id: this.props.incident.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: IncidentMutationRelationDelete,
        variables: {
          id: this.props.incident.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, incident, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], incident) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], incident),
        value: pathOr(null, ['createdBy', 'id'], incident),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(incident);
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(incident);
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
    )(incident);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={IncidentValidation(t)}
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

IncidentEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  incident: PropTypes.object,
  context: PropTypes.array,
};

const IncidentEditionOverview = createFragmentContainer(
  IncidentEditionOverviewComponent,
  {
    incident: graphql`
      fragment IncidentEditionOverview_incident on Incident {
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
)(IncidentEditionOverview);
