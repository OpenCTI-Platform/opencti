import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { compose, defaultTo, lensProp, over, pickAll } from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import { commitMutation, requestSubscription } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import Drawer from '../../common/drawer/Drawer';

const subscription = graphql`
  subscription KillChainPhaseEditionSubscription($id: ID!) {
    killChainPhase(id: $id) {
      ...KillChainPhasesLine_node
    }
  }
`;

const killChainPhaseMutationFieldPatch = graphql`
  mutation KillChainPhaseEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    killChainPhaseEdit(id: $id) {
      fieldPatch(input: $input) {
        ...KillChainPhasesLine_node
      }
    }
  }
`;

const killChainPhaseEditionFocus = graphql`
  mutation KillChainPhaseEditionFocusMutation($id: ID!, $input: EditContext!) {
    killChainPhaseEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const killChainPhaseValidation = (t) => Yup.object().shape({
  kill_chain_name: Yup.string().required(t('This field is required')),
  phase_name: Yup.string().required(t('This field is required')),
  x_opencti_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number')),
});

class KillChainPhaseEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.sub = requestSubscription({
      subscription,
      variables: { id: props.killChainPhase.id },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  handleChangeFocus(name) {
    commitMutation({
      mutation: killChainPhaseEditionFocus,
      variables: {
        id: this.props.killChainPhase.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    killChainPhaseValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: killChainPhaseMutationFieldPatch,
          variables: {
            id: this.props.killChainPhase.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, open, handleClose, killChainPhase } = this.props;
    const { editContext } = killChainPhase;
    const initialValues = over(
      lensProp('x_opencti_order'),
      defaultTo(''),
      pickAll(
        ['kill_chain_name', 'phase_name', 'x_opencti_order'],
        killChainPhase,
      ),
    );
    return (
      <Drawer
        title={t('Update a kill chain phase')}
        open={open}
        onClose={handleClose}
        context={editContext}
      >
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={killChainPhaseValidation(t)}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="kill_chain_name"
                label={t('Kill chain name')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="kill_chain_name"
                  />
                }
              />
              <Field
                component={TextField}
                variant="standard"
                name="phase_name"
                label={t('Phase name')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="phase_name"
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

KillChainPhaseEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  killChainPhase: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n)(KillChainPhaseEditionContainer);
