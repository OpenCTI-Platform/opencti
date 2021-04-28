import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc, compose, join, pick, pipe, split,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat } from '../../../../utils/Time';
import OpenVocabField from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IntrusionSetEditionDetails_intrusionSet
        ...IntrusionSet_intrusionSet
      }
    }
  }
`;

const intrusionSetEditionDetailsFocus = graphql`
  mutation IntrusionSetEditionDetailsFocusMutation(
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

const intrusionSetValidation = (t) => Yup.object().shape({
  first_seen: Yup.date().typeError(
    t('The value must be a date (YYYY-MM-DD)'),
  ),
  last_seen: Yup.date().typeError(t('The value must be a date (YYYY-MM-DD)')),
  resource_level: Yup.string(),
  primary_motivation: Yup.string(),
  secondary_motivations: Yup.array(),
  goals: Yup.string(),
});

class IntrusionSetEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: intrusionSetEditionDetailsFocus,
      variables: {
        id: this.props.intrusionSet.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    let finalValue = value;
    if (name === 'goals') {
      finalValue = split('\n', value);
    }
    intrusionSetValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: intrusionSetMutationFieldPatch,
          variables: {
            id: this.props.intrusionSet.id,
            input: { key: name, value: finalValue },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, intrusionSet, context } = this.props;
    const initialValues = pipe(
      assoc('first_seen', dateFormat(intrusionSet.first_seen)),
      assoc('last_seen', dateFormat(intrusionSet.last_seen)),
      assoc(
        'secondary_motivations',
        intrusionSet.secondary_motivations
          ? intrusionSet.secondary_motivations
          : [],
      ),
      assoc('goals', join('\n', intrusionSet.goals ? intrusionSet.goals : [])),
      pick([
        'first_seen',
        'last_seen',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'goals',
      ]),
    )(intrusionSet);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={intrusionSetValidation(t)}
        onSubmit={() => true}
      >
        {() => (
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
          </Form>
        )}
      </Formik>
    );
  }
}

IntrusionSetEditionDetailsComponent.propTypes = {
  t: PropTypes.func,
  intrusionSet: PropTypes.object,
  context: PropTypes.array,
};

const IntrusionSetEditionDetails = createFragmentContainer(
  IntrusionSetEditionDetailsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetEditionDetails_intrusionSet on IntrusionSet {
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

export default compose(inject18n)(IntrusionSetEditionDetails);
