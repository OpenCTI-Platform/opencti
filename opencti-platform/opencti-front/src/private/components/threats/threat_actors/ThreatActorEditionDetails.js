import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  compose, pipe, split, assoc, join, pick,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';

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

const threatActorMutationFieldPatch = graphql`
  mutation ThreatActorEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ThreatActorEditionDetails_threatActor
      }
    }
  }
`;

const threatActorEditionDetailsFocus = graphql`
  mutation ThreatActorEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const threatActorValidation = (t) => Yup.object().shape({
  sophistication: Yup.string().required(t('This field is required')),
  resource_level: Yup.string().required(t('This field is required')),
  primary_motivation: Yup.string().required(t('This field is required')),
  secondary_motivations: Yup.array().required(t('This field is required')),
  personal_motivations: Yup.array().required(t('This field is required')),
  goals: Yup.string(),
});

class ThreatActorEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: threatActorEditionDetailsFocus,
      variables: {
        id: this.props.threatActor.id,
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
    threatActorValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: threatActorMutationFieldPatch,
          variables: {
            id: this.props.threatActor.id,
            input: { key: name, value: finalValue },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, threatActor, context } = this.props;
    const initialValues = pipe(
      assoc(
        'secondary_motivations',
        threatActor.secondary_motivations
          ? threatActor.secondary_motivations
          : [],
      ),
      assoc(
        'personal_motivations',
        threatActor.personal_motivations ? threatActor.personal_motivations : [],
      ),
      assoc('goals', join('\n', threatActor.goals ? threatActor.goals : [])),
      pick([
        'sophistication',
        'resource_level',
        'primary_motivation',
        'secondary_motivations',
        'personal_motivations',
        'goals',
      ]),
    )(threatActor);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={threatActorValidation(t)}
          onSubmit={() => true}
        >
          {() => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={SelectField}
                  name="sophistication"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Sophistication')}
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
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
                  <MenuItem
                    key="organizational-gain"
                    value="organizational-gain"
                  >
                    {t('motivation_organizational-gain')}
                  </MenuItem>
                  <MenuItem key="individualal-gain" value="individualal-gain">
                    {t('motivation_individualal-gain')}
                  </MenuItem>
                  <MenuItem
                    key="individualal-satisfaction"
                    value="individualal-satisfaction"
                  >
                    {t('motivation_individualal-satisfaction')}
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
                  name="secondary_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Secondary motivations')}
                  fullWidth={true}
                  multiple={true}
                  containerstyle={{ width: '100%', marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="secondary_motivations"
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
                  <MenuItem key="individualal-gain" value="individualal-gain">
                    {t('motivation_individualal-gain')}
                  </MenuItem>
                  <MenuItem
                    key="individualal-satisfaction"
                    value="individualal-satisfaction"
                  >
                    {t('motivation_individualal-satisfaction')}
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
                  name="personal_motivations"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Personal motivations')}
                  fullWidth={true}
                  multiple={true}
                  containerstyle={{ width: '100%', marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="personal_motivations"
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
                  <MenuItem key="individualal-gain" value="individualal-gain">
                    {t('motivation_individualal-gain')}
                  </MenuItem>
                  <MenuItem
                    key="individualal-satisfaction"
                    value="individualal-satisfaction"
                  >
                    {t('motivation_individualal-satisfaction')}
                  </MenuItem>
                  <MenuItem key="revenge" value="revenge">
                    {t('motivation_revenge')}
                  </MenuItem>
                  <MenuItem key="unpredictable" value="unpredictable">
                    {t('motivation_unpredictable')}
                  </MenuItem>
                </Field>
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
            </div>
          )}
        </Formik>
      </div>
    );
  }
}

ThreatActorEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  threatActor: PropTypes.object,
  context: PropTypes.array,
};

const ThreatActorEditionDetails = createFragmentContainer(
  ThreatActorEditionDetailsComponent,
  {
    threatActor: graphql`
      fragment ThreatActorEditionDetails_threatActor on ThreatActor {
        id
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        personal_motivations
        goals
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ThreatActorEditionDetails);
