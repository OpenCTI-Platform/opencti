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
import OpenVocabField from '../../common/form/OpenVocabField';
import { dateFormat } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';

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
        ...ThreatActor_threatActor
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
  first_seen: Yup.date().typeError(
    t('The value must be a date (YYYY-MM-DD)'),
  ),
  last_seen: Yup.date().typeError(t('The value must be a date (YYYY-MM-DD)')),
  sophistication: Yup.string(),
  resource_level: Yup.string(),
  primary_motivation: Yup.string(),
  secondary_motivations: Yup.array(),
  personal_motivations: Yup.array(),
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
      assoc('first_seen', dateFormat(threatActor.first_seen)),
      assoc('last_seen', dateFormat(threatActor.last_seen)),
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
        'first_seen',
        'last_seen',
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
                  component={DatePickerField}
                  name="first_seen"
                  label={t('First seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="first_seen"
                    />
                  }
                />
                <Field
                  component={DatePickerField}
                  name="last_seen"
                  label={t('Last seen')}
                  invalidDateMessage={t(
                    'The value must be a date (YYYY-MM-DD)',
                  )}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      context={context}
                      fieldName="last_seen"
                    />
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
                <OpenVocabField
                  label={t('Personal motivations')}
                  type="attack-motivation-ov"
                  name="personal_motivations"
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
