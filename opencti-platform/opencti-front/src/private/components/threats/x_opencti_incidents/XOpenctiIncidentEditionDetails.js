import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, pick, pipe,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { dateFormat } from '../../../../utils/Time';

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

const xOpenctiIncidentMutationFieldPatch = graphql`
  mutation XOpenctiIncidentEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    xOpenctiIncidentEdit(id: $id) {
      fieldPatch(input: $input) {
        ...XOpenctiIncidentEditionDetails_xOpenctiIncident
      }
    }
  }
`;

const xOpenctiIncidentEditionDetailsFocus = graphql`
  mutation XOpenctiIncidentEditionDetailsFocusMutation($id: ID!, $input: EditContext!) {
    xOpenctiIncidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const xOpenctiIncidentValidation = (t) => Yup.object().shape({
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  objective: Yup.string(),
});

class XOpenctiIncidentEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: xOpenctiIncidentEditionDetailsFocus,
      variables: {
        id: this.props.xOpenctiIncident.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    xOpenctiIncidentValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: xOpenctiIncidentMutationFieldPatch,
          variables: {
            id: this.props.xOpenctiIncident.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, xOpenctiIncident, context } = this.props;
    const initialValues = pipe(
      assoc('first_seen', dateFormat(xOpenctiIncident.first_seen)),
      assoc('last_seen', dateFormat(xOpenctiIncident.last_seen)),
      pick(['first_seen', 'last_seen', 'objective']),
    )(xOpenctiIncident);

    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={xOpenctiIncidentValidation(t)}
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
              component={TextField}
              name="objective"
              label={t('Objective')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="objective" />
              }
            />
          </Form>
        )}
      </Formik>
    );
  }
}

XOpenctiIncidentEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  xOpenctiIncident: PropTypes.object,
  context: PropTypes.array,
};

const XOpenctiXOpenctiIncidentEditionDetails = createFragmentContainer(
  XOpenctiIncidentEditionDetailsComponent,
  {
    xOpenctiIncident: graphql`
      fragment XOpenctiIncidentEditionDetails_xOpenctiIncident on XOpenctiIncident {
        id
        first_seen
        last_seen
        objective
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(XOpenctiXOpenctiIncidentEditionDetails);
