/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import * as Yup from 'yup';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

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

const networkMutationFieldPatch = graphql`
  mutation NetworkEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...NetworkEditionOverview_network
        ...Network_network
      }
    }
  }
`;

export const networkEditionOverviewFocus = graphql`
  mutation NetworkEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const networkMutationRelationAdd = graphql`
  mutation NetworkEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    intrusionSetEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...NetworkEditionOverview_network
        }
      }
    }
  }
`;

const networkMutationRelationDelete = graphql`
  mutation NetworkEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    intrusionSetEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...NetworkEditionOverview_network
      }
    }
  }
`;

const networkValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class NetworkEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: networkEditionOverviewFocus,
      variables: {
        id: this.props.network.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: networkMutationFieldPatch,
      variables: {
        id: this.props.network.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
      },
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      networkValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: networkMutationFieldPatch,
            variables: {
              id: this.props.network.id,
              input: { key: name, value: value || '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: networkMutationFieldPatch,
        variables: {
          id: this.props.network.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { network } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(network);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: networkMutationRelationAdd,
          variables: {
            id: this.props.network.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: networkMutationRelationDelete,
          variables: {
            id: this.props.network.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const {
      t, network, context, enableReferences,
    } = this.props;
    const createdBy = R.pathOr(null, ['createdBy', 'name'], network) === null
      ? ''
      : {
        label: R.pathOr(null, ['createdBy', 'name'], network),
        value: R.pathOr(null, ['createdBy', 'id'], network),
      };
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(network);
    const objectMarking = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(network);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('killChainPhases', killChainPhases),
      R.assoc('objectMarking', objectMarking),
      R.pick([
        'name',
        'confidence',
        'description',
        'createdBy',
        'killChainPhases',
        'objectMarking',
      ]),
    )(network);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={networkValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm, isSubmitting, validateForm, setFieldValue,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              // helperText={
              //   <SubscriptionFocus context={context} fieldName="name" />
              // }
            />
            <ConfidenceField
              name="confidence"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Confidence')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              editContext={context}
              variant="edit"
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
              // helperText={
              //   <SubscriptionFocus context={context} fieldName="description" />
              // }
            />
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              // helpertext={
              //   <SubscriptionFocus context={context} fieldName="createdBy" />
              // }
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              // helpertext={
              //   <SubscriptionFocus
              //     context={context}
              //     fieldname="objectMarking"
              //   />
              // }
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

NetworkEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  network: PropTypes.object,
  context: PropTypes.array,
};

const NetworkEditionOverview = createFragmentContainer(
  NetworkEditionOverviewComponent,
  {
    network: graphql`
      fragment NetworkEditionOverview_network on IntrusionSet {
        id
        name
        confidence
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

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NetworkEditionOverview);
