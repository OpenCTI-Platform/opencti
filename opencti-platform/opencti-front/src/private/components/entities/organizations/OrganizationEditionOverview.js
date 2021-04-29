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

const organizationMutationFieldPatch = graphql`
  mutation OrganizationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    organizationEdit(id: $id) {
      fieldPatch(input: $input) {
        ...OrganizationEditionOverview_organization
        ...Organization_organization
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
    $input: StixMetaRelationshipAddInput!
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
    $toId: String!
    $relationship_type: String!
  ) {
    organizationEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
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
  contact_information: Yup.string(),
  x_opencti_organization_type: Yup.string().required(
    t('This field is required'),
  ),
  x_opencti_reliability: Yup.string().required(t('This field is required')),
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

  handleChangeCreatedBy(name, value) {
    const { organization } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], organization),
      value: pathOr(null, ['createdBy', 'id'], organization),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: organizationMutationRelationAdd,
        variables: {
          id: this.props.organization.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: organizationMutationRelationDelete,
        variables: {
          id: this.props.organization.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: organizationMutationRelationAdd,
          variables: {
            id: this.props.organization.id,
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
    const { organization } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
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
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: organizationMutationRelationDelete,
        variables: {
          id: this.props.organization.id,
          toId: head(removed).value,
          relationship_type: 'created-by',
        },
      });
    }
  }

  render() {
    const { t, organization, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], organization) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], organization),
        value: pathOr(null, ['createdBy', 'id'], organization),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(organization);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      pick([
        'name',
        'description',
        'contact_information',
        'x_opencti_organization_type',
        'x_opencti_reliability',
        'createdBy',
        'objectMarking',
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
            <Field
              component={TextField}
              name="contact_information"
              label={t('Contact information')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="contact_information"
                />
              }
            />
            <Field
              component={SelectField}
              name="x_opencti_organization_type"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Organization type')}
              fullWidth={true}
              inputProps={{
                name: 'x_opencti_organization_type',
                id: 'x_opencti_organization_type',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_organization_type"
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
              name="x_opencti_reliability"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Reliability')}
              fullWidth={true}
              inputProps={{
                name: 'x_opencti_reliability',
                id: 'x_opencti_reliability',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_reliability"
                />
              }
            >
              <MenuItem value="A">{t('reliability_A')}</MenuItem>
              <MenuItem value="B">{t('reliability_B')}</MenuItem>
              <MenuItem value="C">{t('reliability_C')}</MenuItem>
              <MenuItem value="D">{t('reliability_D')}</MenuItem>
              <MenuItem value="E">{t('reliability_E')}</MenuItem>
              <MenuItem value="F">{t('reliability_F')}</MenuItem>
            </Field>
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
        contact_information
        x_opencti_organization_type
        x_opencti_reliability
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
)(OrganizationEditionOverview);
