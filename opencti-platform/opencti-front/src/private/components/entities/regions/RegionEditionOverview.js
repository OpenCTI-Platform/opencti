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
import CreatedByRefField from '../../common/form/CreatedByRefField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';

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

const regionMutationFieldPatch = graphql`
  mutation RegionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    regionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...RegionEditionOverview_region
      }
    }
  }
`;

export const regionEditionOverviewFocus = graphql`
  mutation RegionEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    regionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const regionMutationRelationAdd = graphql`
  mutation RegionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    regionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RegionEditionOverview_region
        }
      }
    }
  }
`;

const regionMutationRelationDelete = graphql`
  mutation RegionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    regionEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...RegionEditionOverview_region
      }
    }
  }
`;

const regionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class RegionEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: regionEditionOverviewFocus,
      variables: {
        id: this.props.region.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    regionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: regionMutationFieldPatch,
          variables: { id: this.props.region.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { region } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], region),
      value: pathOr(null, ['createdByRef', 'node', 'id'], region),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], region),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: regionMutationRelationAdd,
        variables: {
          id: this.props.region.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: regionMutationRelationDelete,
        variables: {
          id: this.props.region.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: regionMutationRelationAdd,
          variables: {
            id: this.props.region.id,
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
  }

  handleChangeMarkingDefinitions(name, values) {
    const { region } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(region);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: regionMutationRelationAdd,
        variables: {
          id: this.props.region.id,
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
        mutation: regionMutationRelationDelete,
        variables: {
          id: this.props.region.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, region, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], region) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], region),
        value: pathOr(null, ['createdByRef', 'node', 'id'], region),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], region),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(region);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'description', 'createdByRef', 'markingDefinitions']),
    )(region);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={regionValidation(t)}
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
                  <SubscriptionFocus
                    context={context}
                    fieldName="description"
                  />
                }
              />
              <CreatedByRefField
                name="createdByRef"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="createdByRef"
                  />
                }
                onChange={this.handleChangeCreatedByRef.bind(this)}
              />
              <MarkingDefinitionsField
                name="markingDefinitions"
                style={{ marginTop: 20, width: '100%' }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="markingDefinitions"
                  />
                }
                onChange={this.handleChangeMarkingDefinitions.bind(this)}
              />
            </Form>
          )}
        </Formik>
      </div>
    );
  }
}

RegionEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  region: PropTypes.object,
  context: PropTypes.array,
};

const RegionEditionOverview = createFragmentContainer(
  RegionEditionOverviewComponent,
  {
    region: graphql`
      fragment RegionEditionOverview_region on Region {
        id
        name
        description
        createdByRef {
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
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RegionEditionOverview);
