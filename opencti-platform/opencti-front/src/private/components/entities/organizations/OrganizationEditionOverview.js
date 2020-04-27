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
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
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

const organizationMutationFieldPatch = graphql`
  mutation OrganizationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    organizationEdit(id: $id) {
      fieldPatch(input: $input) {
        ...OrganizationEditionOverview_organization
      }
    }
  }
`;

export const organizationEditionOverviewFocus = graphql`
  mutation OrganizationEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    organizationEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const organizationMutationRelationAdd = graphql`
  mutation OrganizationEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    organizationEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...OrganizationEditionOverview_organization
        }
      }
    }
  }
`;

const organizationMutationRelationDelete = graphql`
  mutation OrganizationEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    organizationEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...OrganizationEditionOverview_organization
      }
    }
  }
`;

const organizationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  organization_class: Yup.string().required(t('This field is required')),
  reliability: Yup.string().required(t('This field is required')),
});

class OrganizationEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: organizationEditionOverviewFocus,
      variables: {
        id: this.props.organization.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    organizationValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: organizationMutationFieldPatch,
          variables: {
            id: this.props.organization.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { organization } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], organization),
      value: pathOr(null, ['createdByRef', 'node', 'id'], organization),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], organization),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: organizationMutationRelationAdd,
        variables: {
          id: this.props.organization.id,
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
        mutation: organizationMutationRelationDelete,
        variables: {
          id: this.props.organization.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: organizationMutationRelationAdd,
          variables: {
            id: this.props.organization.id,
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
    const { organization } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(organization);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: organizationMutationRelationAdd,
        variables: {
          id: this.props.organization.id,
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
        mutation: organizationMutationRelationDelete,
        variables: {
          id: this.props.organization.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, organization, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], organization) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], organization),
        value: pathOr(null, ['createdByRef', 'node', 'id'], organization),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          organization,
        ),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(organization);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'description',
        'organization_class',
        'reliability',
        'createdByRef',
        'markingDefinitions',
      ]),
    )(organization);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={organizationValidation(t)}
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
            <Field
              component={SelectField}
              name="organization_class"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Organization type')}
              fullWidth={true}
              inputProps={{
                name: 'organization_class',
                id: 'organization_class',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="organization_class"
                />
              }
            >
              <MenuItem value="constituent">{t('Constituent')}</MenuItem>
              <MenuItem value="csirt">{t('CSIRT')}</MenuItem>
              <MenuItem value="partner">{t('Partner')}</MenuItem>
              <MenuItem value="vendor">{t('Vendor')}</MenuItem>
              <MenuItem value="other">{t('Other')}</MenuItem>
            </Field>
            <Field
              component={SelectField}
              name="reliability"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Reliability')}
              fullWidth={true}
              inputProps={{
                name: 'reliability',
                id: 'reliability',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldName="reliability" />
              }
            >
              <MenuItem value="A">{t('reliability_A')}</MenuItem>
              <MenuItem value="B">{t('reliability_B')}</MenuItem>
              <MenuItem value="C">{t('reliability_C')}</MenuItem>
              <MenuItem value="D">{t('reliability_D')}</MenuItem>
              <MenuItem value="E">{t('reliability_E')}</MenuItem>
              <MenuItem value="F">{t('reliability_F')}</MenuItem>
            </Field>
            <CreatedByRefField
              name="createdByRef"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdByRef" />
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
    );
  }
}

OrganizationEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  organization: PropTypes.object,
  context: PropTypes.array,
};

const OrganizationEditionOverview = createFragmentContainer(
  OrganizationEditionOverviewComponent,
  {
    organization: graphql`
      fragment OrganizationEditionOverview_organization on Organization {
        id
        name
        description
        organization_class
        reliability
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
)(OrganizationEditionOverview);
