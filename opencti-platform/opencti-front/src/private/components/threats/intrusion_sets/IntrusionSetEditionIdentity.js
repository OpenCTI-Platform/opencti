import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, pick, pipe,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import DatePickerField from '../../../../components/DatePickerField';
import Select from '../../../../components/Select';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation, WS_ACTIVATED } from '../../../../relay/environment';
import { dateFormat } from '../../../../utils/Time';

const styles = theme => ({
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

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionIdentityFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IntrusionSetEditionIdentity_intrusionSet
      }
    }
  }
`;

const intrusionSetEditionIdentityFocus = graphql`
  mutation IntrusionSetEditionIdentityFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        ...IntrusionSetEditionIdentity_intrusionSet
      }
    }
  }
`;

const intrusionSetValidation = t => Yup.object().shape({
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

class IntrusionSetEditionIdentityComponent extends Component {
  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: intrusionSetEditionIdentityFocus,
        variables: {
          id: this.props.intrusionSet.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
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
    const {
      t, intrusionSet, editUsers, me,
    } = this.props;
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
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={intrusionSetValidation(t)}
          onSubmit={() => true}
          render={() => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="first_seen"
                  component={DatePickerField}
                  label={t('First seen')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="first_seen"
                    />
                  }
                />
                <Field
                  name="last_seen"
                  component={DatePickerField}
                  label={t('Last seen')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="last_seen"
                    />
                  }
                />
                <Field
                  name="sophistication"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Sophistication')}
                  fullWidth={true}
                  inputProps={{
                    name: 'sophistication',
                    id: 'sophistication',
                  }}
                  containerstyle={{ width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  name="resource_level"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Resource level')}
                  fullWidth={true}
                  inputProps={{
                    name: 'resource_level',
                    id: 'resource_level',
                  }}
                  containerstyle={{ width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  name="primary_motivation"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Primary motivation')}
                  fullWidth={true}
                  inputProps={{
                    name: 'primary_motivation',
                    id: 'primary_motivation',
                  }}
                  containerstyle={{ width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  <MenuItem
                    key="organizational-gain"
                    value="organizational-gain"
                  >
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
                  name="secondary_motivation"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Secondary motivation')}
                  fullWidth={true}
                  inputProps={{
                    name: 'secondary_motivation',
                    id: 'secondary_motivation',
                  }}
                  containerstyle={{ width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
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
                  <MenuItem
                    key="organizational-gain"
                    value="organizational-gain"
                  >
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
            </div>
          )}
        />
      </div>
    );
  }
}

IntrusionSetEditionIdentityComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  intrusionSet: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const IntrusionSetEditionIdentity = createFragmentContainer(
  IntrusionSetEditionIdentityComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetEditionIdentity_intrusionSet on IntrusionSet {
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

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IntrusionSetEditionIdentity);
