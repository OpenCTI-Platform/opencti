import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
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

const systemMutationFieldPatch = graphql`
  mutation SystemEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    systemEdit(id: $id) {
      fieldPatch(input: $input) {
        ...SystemEditionOverview_system
        ...System_system
      }
    }
  }
`;

export const systemEditionOverviewFocus = graphql`
  mutation SystemEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    systemEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const systemMutationRelationAdd = graphql`
  mutation SystemEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    systemEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...SystemEditionOverview_system
        }
      }
    }
  }
`;

const systemMutationRelationDelete = graphql`
  mutation SystemEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    systemEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...SystemEditionOverview_system
      }
    }
  }
`;

const systemValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  contact_information: Yup.string().nullable(),
  x_opencti_workflow_id: Yup.object(),
});

class SystemEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: systemEditionOverviewFocus,
      variables: {
        id: this.props.system.id,
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
    systemValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: systemMutationFieldPatch,
          variables: {
            id: this.props.system.id,
            input: { key: name, value: finalValue ?? '' },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: systemMutationFieldPatch,
        variables: {
          id: this.props.system.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    const { system } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(system);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: systemMutationRelationAdd,
        variables: {
          id: this.props.system.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: systemMutationRelationDelete,
        variables: {
          id: this.props.system.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, system, context } = this.props;
    const external = system.external === true;
    const createdBy = convertCreatedBy(system);
    const objectMarking = convertMarkings(system);
    const status = convertStatus(t, system);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      assoc('x_opencti_workflow_id', status),
      pick([
        'name',
        'description',
        'contact_information',
        'createdBy',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(system);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={systemValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              disabled={external}
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
              variant="standard"
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
            {system.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="System"
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
        )}
      </Formik>
    );
  }
}

SystemEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  system: PropTypes.object,
  context: PropTypes.array,
};

const SystemEditionOverview = createFragmentContainer(
  SystemEditionOverviewComponent,
  {
    system: graphql`
      fragment SystemEditionOverview_system on System {
        id
        name
        description
        contact_information
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

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SystemEditionOverview);
