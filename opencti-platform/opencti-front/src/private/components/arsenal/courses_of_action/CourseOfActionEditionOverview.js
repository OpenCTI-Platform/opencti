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

const courseOfActionMutationFieldPatch = graphql`
  mutation CourseOfActionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    courseOfActionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CourseOfActionEditionOverview_courseOfAction
        ...CourseOfAction_courseOfAction
      }
    }
  }
`;

export const courseOfActionEditionOverviewFocus = graphql`
  mutation CourseOfActionEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    courseOfActionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const courseOfActionMutationRelationAdd = graphql`
  mutation CourseOfActionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    courseOfActionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CourseOfActionEditionOverview_courseOfAction
        }
      }
    }
  }
`;

const courseOfActionMutationRelationDelete = graphql`
  mutation CourseOfActionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    courseOfActionEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CourseOfActionEditionOverview_courseOfAction
      }
    }
  }
`;

const courseOfActionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class CourseOfActionEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: courseOfActionEditionOverviewFocus,
      variables: {
        id: this.props.courseOfAction.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    courseOfActionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: courseOfActionMutationFieldPatch,
          variables: {
            id: this.props.courseOfAction.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { courseOfAction } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], courseOfAction),
      value: pathOr(null, ['createdBy', 'id'], courseOfAction),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: courseOfActionMutationRelationAdd,
        variables: {
          id: this.props.courseOfAction.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: courseOfActionMutationRelationDelete,
        variables: {
          id: this.props.courseOfAction.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: courseOfActionMutationRelationAdd,
          variables: {
            id: this.props.courseOfAction.id,
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
    const { courseOfAction } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(courseOfAction);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: courseOfActionMutationRelationAdd,
        variables: {
          id: this.props.courseOfAction.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: courseOfActionMutationRelationDelete,
        variables: {
          id: this.props.courseOfAction.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, courseOfAction, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], courseOfAction) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], courseOfAction),
        value: pathOr(null, ['createdBy', 'id'], courseOfAction),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(courseOfAction);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      pick([
        'name',
        'description',
        'createdBy',
        'killChainPhases',
        'objectMarking',
      ]),
    )(courseOfAction);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={courseOfActionValidation(t)}
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

CourseOfActionEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  courseOfAction: PropTypes.object,
  context: PropTypes.array,
};

const CourseOfActionEditionOverview = createFragmentContainer(
  CourseOfActionEditionOverviewComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionEditionOverview_courseOfAction on CourseOfAction {
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
)(CourseOfActionEditionOverview);
