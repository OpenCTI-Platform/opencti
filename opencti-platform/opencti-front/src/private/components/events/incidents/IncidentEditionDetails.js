import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { buildDate, parse } from '../../../../utils/Time';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
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

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    incidentEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IncidentEditionDetails_incident
      }
    }
  }
`;

const incidentEditionDetailsFocus = graphql`
  mutation IncidentEditionDetailsFocusMutation($id: ID!, $input: EditContext!) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const incidentValidation = (t) => Yup.object().shape({
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  objective: Yup.string().nullable(),
});

class IncidentEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: incidentEditionDetailsFocus,
      variables: {
        id: this.props.incident.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: incidentMutationFieldPatch,
      variables: {
        id: this.props.campaign.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      incidentValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: incidentMutationFieldPatch,
            variables: {
              id: this.props.incident.id,
              input: {
                key: name,
                value: value || '',
              },
            },
          });
        })
        .catch(() => false);
    }
  }

  render() {
    const { t, incident, context, enableReferences } = this.props;
    const isInferred = incident.is_inferred;
    const initialValues = R.pipe(
      R.assoc('first_seen', buildDate(incident.first_seen)),
      R.assoc('last_seen', buildDate(incident.last_seen)),
      R.pick(['first_seen', 'last_seen', 'objective']),
    )(incident);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={incidentValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {(submitForm, isSubmitting, validateForm, setFieldValue, values) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={DateTimePickerField}
              name="first_seen"
              disabled={isInferred}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              TextFieldProps={{
                label: t('First seen'),
                variant: 'standard',
                fullWidth: true,
                helperText: (
                  <SubscriptionFocus context={context} fieldName="first_seen" />
                ),
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_seen"
              label={t('Last seen')}
              disabled={isInferred}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              TextFieldProps={{
                label: t('Last seen'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus context={context} fieldName="last_seen" />
                ),
              }}
            />
            <Field
              component={TextField}
              variant="standard"
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
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
                setFieldValue={setFieldValue}
                values={values}
                id={incident.id}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

IncidentEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  incident: PropTypes.object,
  context: PropTypes.array,
};

const IncidentEditionDetails = createFragmentContainer(
  IncidentEditionDetailsComponent,
  {
    incident: graphql`
      fragment IncidentEditionDetails_incident on Incident {
        id
        first_seen
        last_seen
        objective
        is_inferred
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IncidentEditionDetails);
