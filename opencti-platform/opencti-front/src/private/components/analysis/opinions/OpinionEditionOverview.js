import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
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
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
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

export const opinionMutationFieldPatch = graphql`
  mutation OpinionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
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
    $toId: String!
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
  explanation: Yup.string(),
  confidence: Yup.number(),
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
    opinionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: opinionMutationFieldPatch,
          variables: { id: this.props.opinion.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { opinion } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], opinion),
      value: pathOr(null, ['createdBy', 'id'], opinion),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: opinionMutationRelationAdd,
        variables: {
          id: this.props.opinion.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: opinionMutationRelationDelete,
        variables: {
          id: this.props.opinion.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: opinionMutationRelationAdd,
          variables: {
            id: this.props.opinion.id,
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
    const { opinion } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(opinion);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: opinionMutationRelationAdd,
        variables: {
          id: this.props.opinion.id,
          input: {
            toId: head(added).value,
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
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, opinion, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], opinion) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], opinion),
        value: pathOr(null, ['createdBy', 'id'], opinion),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(opinion);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      pick([
        'attribute_abstract',
        'content',
        'confidence',
        'createdBy',
        'objectMarking',
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
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(OpinionEditionOverview);
