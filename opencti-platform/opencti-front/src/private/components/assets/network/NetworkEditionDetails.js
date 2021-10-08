import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc, compose, join, pick, pipe, split,
} from 'ramda';
import * as Yup from 'yup';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat, parse } from '../../../../utils/Time';
import OpenVocabField from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

const networkMutationFieldPatch = graphql`
  mutation NetworkEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...NetworkEditionDetails_network
        ...Network_network
      }
    }
  }
`;

const networkEditionDetailsFocus = graphql`
  mutation NetworkEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const networkValidation = (t) => Yup.object().shape({
  first_observed: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  last_observed: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  resource_level: Yup.string().nullable(),
  primary_motivation: Yup.string().nullable(),
  secondary_motivations: Yup.array().nullable(),
  goals: Yup.string().nullable(),
});

class NetworkEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: networkEditionDetailsFocus,
      variables: {
        id: this.props.network.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.assoc(
        'goals',
        values.goals && values.goals.length ? R.split('\n', values.goals) : [],
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: networkMutationFieldPatch,
      variables: {
        id: this.props.network.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
      },
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'goals') {
        finalValue = split('\n', value);
      }
      networkValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: networkMutationFieldPatch,
            variables: {
              id: this.props.network.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  render() {
    const {
      t, network, context, enableReferences,
    } = this.props;
    const initialValues = pipe(
      assoc('first_seen', dateFormat(network.first_seen)),
      assoc('last_seen', dateFormat(network.last_seen)),
      assoc(
        'secondary_motivations',
        network.secondary_motivations
          ? network.secondary_motivations
          : [],
      ),
      assoc('goals', join('\n', network.goals ? network.goals : [])),
      pick([
        'first_seen',
        'last_seen',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'goals',
      ]),
    )(network);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={networkValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({ submitForm, isSubmitting, validateForm }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={DatePickerField}
              name="first_seen"
              label={t('First seen')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="first_seen" />
              }
            />
            <Field
              component={DatePickerField}
              name="last_seen"
              label={t('Last seen')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="last_seen" />
              }
            />
            <OpenVocabField
              label={t('Resource level')}
              type="attack-resource-level-ov"
              name="resource_level"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              containerstyle={{ marginTop: 20, width: '100%' }}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <OpenVocabField
              label={t('Primary motivation')}
              type="attack-motivation-ov"
              name="primary_motivation"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              containerstyle={{ marginTop: 20, width: '100%' }}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <OpenVocabField
              label={t('Secondary motivations')}
              type="attack-motivation-ov"
              name="secondary_motivations"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              containerstyle={{ marginTop: 20, width: '100%' }}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            <Field
              component={TextField}
              name="goals"
              label={t('Goals (1 / line)')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="goals" />
              }
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

NetworkEditionDetailsComponent.propTypes = {
  t: PropTypes.func,
  network: PropTypes.object,
  context: PropTypes.array,
};

const NetworkEditionDetails = createFragmentContainer(
  NetworkEditionDetailsComponent,
  {
    network: graphql`
      fragment NetworkEditionDetails_network on IntrusionSet {
        id
        first_seen
        last_seen
        resource_level
        primary_motivation
        secondary_motivations
        goals
      }
    `,
  },
);

export default compose(inject18n)(NetworkEditionDetails);
