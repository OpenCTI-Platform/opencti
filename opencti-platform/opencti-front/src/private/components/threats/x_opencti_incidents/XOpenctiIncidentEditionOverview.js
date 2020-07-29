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

const xOpenctiIncidentMutationFieldPatch = graphql`
  mutation XOpenctiIncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    xOpenctiIncidentEdit(id: $id) {
      fieldPatch(input: $input) {
        ...XOpenctiIncidentEditionOverview_xOpenctiIncident
      }
    }
  }
`;

export const xOpenctiIncidentEditionOverviewFocus = graphql`
  mutation XOpenctiIncidentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    xOpenctiIncidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const xOpenctiIncidentMutationRelationAdd = graphql`
  mutation XOpenctiIncidentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    xOpenctiIncidentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...XOpenctiIncidentEditionOverview_xOpenctiIncident
        }
      }
    }
  }
`;

const xOpenctiIncidentMutationRelationDelete = graphql`
  mutation XOpenctiIncidentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    xOpenctiIncidentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...XOpenctiIncidentEditionOverview_xOpenctiIncident
      }
    }
  }
`;

const xOpenctiIncidentValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class XOpenctiIncidentEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: xOpenctiIncidentEditionOverviewFocus,
      variables: {
        id: this.props.xOpenctiIncident.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    xOpenctiIncidentValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: xOpenctiIncidentMutationFieldPatch,
          variables: {
            id: this.props.xOpenctiIncident.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { xOpenctiIncident } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], xOpenctiIncident),
      value: pathOr(null, ['createdBy', 'id'], xOpenctiIncident),
      relation: pathOr(null, ['createdBy', 'relation', 'id'], xOpenctiIncident),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: xOpenctiIncidentMutationRelationAdd,
        variables: {
          id: this.props.xOpenctiIncident.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: xOpenctiIncidentMutationRelationDelete,
        variables: {
          id: this.props.xOpenctiIncident.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: xOpenctiIncidentMutationRelationAdd,
          variables: {
            id: this.props.xOpenctiIncident.id,
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
    const { xOpenctiIncident } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(xOpenctiIncident);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: xOpenctiIncidentMutationRelationAdd,
        variables: {
          id: this.props.xOpenctiIncident.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: xOpenctiIncidentMutationRelationDelete,
        variables: {
          id: this.props.xOpenctiIncident.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, xOpenctiIncident, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], xOpenctiIncident) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], xOpenctiIncident),
        value: pathOr(null, ['createdBy', 'id'], xOpenctiIncident),
        relation: pathOr(
          null,
          ['createdBy', 'relation', 'id'],
          xOpenctiIncident,
        ),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(xOpenctiIncident);
    const markingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(xOpenctiIncident);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('killChainPhases', killChainPhases),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'description',
        'createdBy',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(xOpenctiIncident);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={xOpenctiIncidentValidation(t)}
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
              component={TextField}
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

XOpenctiIncidentEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  xOpenctiIncident: PropTypes.object,
  context: PropTypes.array,
};

const XOpenctiXOpenctiIncidentEditionOverview = createFragmentContainer(
  XOpenctiIncidentEditionOverviewComponent,
  {
    xOpenctiIncident: graphql`
      fragment XOpenctiIncidentEditionOverview_xOpenctiIncident on XOpenctiIncident {
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
)(XOpenctiXOpenctiIncidentEditionOverview);
