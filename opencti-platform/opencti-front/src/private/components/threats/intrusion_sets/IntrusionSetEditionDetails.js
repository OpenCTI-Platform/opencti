import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import {
  assoc, compose, pick, pipe,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat } from '../../../../utils/Time';

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IntrusionSetEditionDetails_intrusionSet
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
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  sophistication: Yup.string(),
  resource_level: Yup.string(),
  primary_motivation: Yup.string(),
  secondary_motivation: Yup.string(),
  goal: Yup.string(),
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
    intrusionSetValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: intrusionSetMutationFieldPatch,
          variables: {
            id: this.props.intrusionSet.id,
            input: { key: name, value },
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
      pick([
        'first_seen',
        'last_seen',
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivation',
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
            <Field
              component={SelectField}
              name="sophistication"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Sophistication')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="sophistication"
                />
              }
            >
              <MenuItem key="none" value="none">
                {t('sophistication_none')}
              </MenuItem>
              <MenuItem key="minimal" value="minimal">
                {t('sophistication_minimal')}
              </MenuItem>
              <MenuItem key="intermediate" value="intermediate">
                {t('sophistication_intermediate')}
              </MenuItem>
              <MenuItem key="advanced" value="advanced">
                {t('sophistication_advanced')}
              </MenuItem>
              <MenuItem key="expert" value="expert">
                {t('sophistication_expert')}
              </MenuItem>
              <MenuItem key="innovator" value="innovator">
                {t('sophistication_innovator')}
              </MenuItem>
              <MenuItem key="strategic" value="strategic">
                {t('sophistication_strategic')}
              </MenuItem>
            </Field>
            <Field
              component={SelectField}
              name="resource_level"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Resource level')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="resource_level"
                />
              }
            >
              <MenuItem key="none" value="">
                {t('None')}
              </MenuItem>
              <MenuItem key="individual" value="individual">
                {t('resource_individual')}
              </MenuItem>
              <MenuItem key="club" value="club">
                {t('resource_club')}
              </MenuItem>
              <MenuItem key="contest" value="contest">
                {t('resource_contest')}
              </MenuItem>
              <MenuItem key="team" value="team">
                {t('resource_team')}
              </MenuItem>
              <MenuItem key="organization" value="organization">
                {t('resource_organization')}
              </MenuItem>
              <MenuItem key="government" value="government">
                {t('resource_government')}
              </MenuItem>
            </Field>
            <Field
              component={SelectField}
              name="primary_motivation"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Primary motivation')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="primary_motivation"
                />
              }
            >
              <MenuItem key="none" value="">
                {t('None')}
              </MenuItem>
              <MenuItem key="accidental" value="accidental">
                {t('motivation_accidental')}
              </MenuItem>
              <MenuItem key="coercion" value="coercion">
                {t('motivation_coercion')}
              </MenuItem>
              <MenuItem key="dominance" value="dominance">
                {t('motivation_dominance')}
              </MenuItem>
              <MenuItem key="ideology" value="ideology">
                {t('motivation_ideology')}
              </MenuItem>
              <MenuItem key="notoriety" value="notoriety">
                {t('motivation_notoriety')}
              </MenuItem>
              <MenuItem key="organizational-gain" value="organizational-gain">
                {t('motivation_organizational-gain')}
              </MenuItem>
              <MenuItem key="personal-gain" value="personal-gain">
                {t('motivation_personal-gain')}
              </MenuItem>
              <MenuItem
                key="personal-satisfaction"
                value="personal-satisfaction"
              >
                {t('motivation_personal-satisfaction')}
              </MenuItem>
              <MenuItem key="revenge" value="revenge">
                {t('motivation_revenge')}
              </MenuItem>
              <MenuItem key="unpredictable" value="unpredictable">
                {t('motivation_unpredictable')}
              </MenuItem>
            </Field>
            <Field
              component={SelectField}
              name="secondary_motivation"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Secondary motivation')}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="secondary_motivation"
                />
              }
            >
              <MenuItem key="none" value="">
                {t('None')}
              </MenuItem>
              <MenuItem key="accidental" value="accidental">
                {t('motivation_accidental')}
              </MenuItem>
              <MenuItem key="coercion" value="coercion">
                {t('motivation_coercion')}
              </MenuItem>
              <MenuItem key="dominance" value="dominance">
                {t('motivation_dominance')}
              </MenuItem>
              <MenuItem key="ideology" value="ideology">
                {t('motivation_ideology')}
              </MenuItem>
              <MenuItem key="notoriety" value="notoriety">
                {t('motivation_notoriety')}
              </MenuItem>
              <MenuItem key="organizational-gain" value="organizational-gain">
                {t('motivation_organizational-gain')}
              </MenuItem>
              <MenuItem key="personal-gain" value="personal-gain">
                {t('motivation_personal-gain')}
              </MenuItem>
              <MenuItem
                key="personal-satisfaction"
                value="personal-satisfaction"
              >
                {t('motivation_personal-satisfaction')}
              </MenuItem>
              <MenuItem key="revenge" value="revenge">
                {t('motivation_revenge')}
              </MenuItem>
              <MenuItem key="unpredictable" value="unpredictable">
                {t('motivation_unpredictable')}
              </MenuItem>
            </Field>
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
        sophistication
        resource_level
        primary_motivation
        secondary_motivation
      }
    `,
  },
);

export default compose(inject18n)(IntrusionSetEditionDetails);
