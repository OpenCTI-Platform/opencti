import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import * as Yup from 'yup';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkDownField from '../../../../components/MarkDownField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import StatusField from '../../common/form/StatusField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
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

export const opinionMutationFieldPatch = graphql`
  mutation OpinionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    opinionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...OpinionEditionOverview_opinion
        ...Opinion_opinion
      }
    }
  }
`;

export const opinionEditionOverviewFocus = graphql`
  mutation OpinionEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    opinionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const opinionMutationRelationAdd = graphql`
  mutation OpinionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    opinionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...OpinionEditionOverview_opinion
        }
      }
    }
  }
`;

const opinionMutationRelationDelete = graphql`
  mutation OpinionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    opinionEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...OpinionEditionOverview_opinion
      }
    }
  }
`;

const opinionValidation = (t) => Yup.object().shape({
  opinion: Yup.string().required(t('This field is required')),
  explanation: Yup.string().nullable(),
  confidence: Yup.number(),
  x_opencti_workflow_id: Yup.object(),
});

class OpinionEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: opinionEditionOverviewFocus,
      variables: {
        id: this.props.opinion.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    opinionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: opinionMutationFieldPatch,
          variables: {
            id: this.props.opinion.id,
            input: { key: name, value: finalValue ?? '' },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    commitMutation({
      mutation: opinionMutationFieldPatch,
      variables: {
        id: this.props.opinion.id,
        input: { key: 'createdBy', value: value.value || '' },
      },
    });
  }

  handleChangeObjectMarking(name, values) {
    const { opinion } = this.props;
    const currentMarkingDefinitions = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(opinion);

    const added = R.difference(values, currentMarkingDefinitions);
    const removed = R.difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: opinionMutationRelationAdd,
        variables: {
          id: this.props.opinion.id,
          input: {
            toId: R.head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: opinionMutationRelationDelete,
        variables: {
          id: this.props.opinion.id,
          toId: R.head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, opinion, context } = this.props;
    const createdBy = convertCreatedBy(opinion);
    const objectMarking = convertMarkings(opinion);
    const status = convertStatus(t, opinion);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('x_opencti_workflow_id', status),
      R.pick([
        'attribute_abstract',
        'content',
        'confidence',
        'createdBy',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(opinion);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={opinionValidation(t)}
      >
        {({ setFieldValue }) => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="opinion"
                label={t('Opinion')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="opinion" />
                }
              />
              <Field
                component={MarkDownField}
                name="explanation"
                label={t('Explanation')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="content" />
                }
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
              {opinion.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="Opinion"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
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
          </div>
        )}
      </Formik>
    );
  }
}

OpinionEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  opinion: PropTypes.object,
  context: PropTypes.array,
};

const OpinionEditionOverview = createFragmentContainer(
  OpinionEditionOverviewComponent,
  {
    opinion: graphql`
      fragment OpinionEditionOverview_opinion on Opinion {
        id
        opinion
        explanation
        confidence
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
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(OpinionEditionOverview);
