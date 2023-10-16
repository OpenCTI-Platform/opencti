import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import { commitMutation, requestSubscription } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import Drawer from '../../common/drawer/Drawer';

const subscription = graphql`
  subscription MarkingDefinitionEditionSubscription($id: ID!) {
    markingDefinition(id: $id) {
      ...MarkingDefinitionEdition_markingDefinition
    }
  }
`;

const markingDefinitionMutationFieldPatch = graphql`
  mutation MarkingDefinitionEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    markingDefinitionEdit(id: $id) {
      fieldPatch(input: $input) {
        ...MarkingDefinitionEdition_markingDefinition
      }
    }
  }
`;

const markingDefinitionEditionFocus = graphql`
  mutation MarkingDefinitionEditionFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    markingDefinitionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const markingDefinitionValidation = (t) => Yup.object().shape({
  definition_type: Yup.string().required(t('This field is required')),
  definition: Yup.string().required(t('This field is required')),
  x_opencti_color: Yup.string().required(t('This field is required')),
  x_opencti_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

class MarkingDefinitionEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.markingDefinition.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: markingDefinitionEditionFocus,
      variables: {
        id: this.props.markingDefinition.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    markingDefinitionValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: markingDefinitionMutationFieldPatch,
          variables: {
            id: this.props.markingDefinition.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, open, handleClose, markingDefinition } = this.props;
    const { editContext } = markingDefinition;
    const initialValues = pick(
      ['definition_type', 'definition', 'x_opencti_color', 'x_opencti_order'],
      markingDefinition,
    );
    return (
      <Drawer
        title={t('Update a marking definition')}
        open={open}
        onClose={handleClose}
        context={editContext}
      >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={markingDefinitionValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition_type"
                  label={t('Type')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="definition_type"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition"
                  label={t('Definition')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="definition"
                    />
                  }
                />
                <Field
                  component={ColorPickerField}
                  name="x_opencti_color"
                  label={t('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_color"
                    />
                  }
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="x_opencti_order"
                    />
                  }
                />
              </Form>
            )}
          </Formik>
      </Drawer>
    );
  }
}

MarkingDefinitionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  markingDefinition: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const MarkingDefinitionEditionFragment = createFragmentContainer(
  MarkingDefinitionEditionContainer,
  {
    markingDefinition: graphql`
      fragment MarkingDefinitionEdition_markingDefinition on MarkingDefinition {
        id
        definition_type
        definition
        x_opencti_color
        x_opencti_order
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
)(MarkingDefinitionEditionFragment);
