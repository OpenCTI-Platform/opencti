import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
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
  subscription LabelEditionSubscription($id: ID!) {
    label(id: $id) {
      ...LabelsLine_node
    }
  }
`;

const labelMutationFieldPatch = graphql`
  mutation LabelEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    labelEdit(id: $id) {
      fieldPatch(input: $input) {
        ...LabelsLine_node
      }
    }
  }
`;

const labelEditionFocus = graphql`
  mutation LabelEditionFocusMutation($id: ID!, $input: EditContext!) {
    labelEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const labelValidation = (t) => Yup.object().shape({
  value: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

class LabelEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.label.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: labelEditionFocus,
      variables: {
        id: this.props.label.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    labelValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: labelMutationFieldPatch,
          variables: {
            id: this.props.label.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, handleClose, label, open } = this.props;
    const { editContext } = label;
    const initialValues = pick(['value', 'color'], label);
    return (
      <Drawer
        title={t('Update a label')}
        open={open}
        onClose={handleClose}
        context={editContext}
      >
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={labelValidation(t)}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="value"
                label={t('Value')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="value"
                  />
                }
              />
              <Field
                component={ColorPickerField}
                name="color"
                label={t('Color')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="color"
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

LabelEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  label: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n)(LabelEditionContainer);
