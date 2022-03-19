import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';

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

export const externalReferenceMutationFieldPatch = graphql`
  mutation ExternalReferenceEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    externalReferenceEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ExternalReferenceEditionOverview_externalReference
        ...ExternalReference_externalReference
      }
    }
  }
`;

export const externalReferenceEditionOverviewFocus = graphql`
  mutation ExternalReferenceEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    externalReferenceEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const externalReferenceValidation = (t) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string().nullable(),
  url: Yup.string().url(t('The value must be an URL')).nullable(),
  description: Yup.string().nullable(),
});

class ExternalReferenceEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: externalReferenceEditionOverviewFocus,
      variables: {
        id: this.props.externalReference.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    externalReferenceValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: externalReferenceMutationFieldPatch,
          variables: {
            id: this.props.externalReference.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, externalReference, context } = this.props;
    const initialValues = pick(
      ['source_name', 'external_id', 'url', 'description'],
      externalReference,
    );
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={externalReferenceValidation(t)}
      >
        {() => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="source_name"
                label={t('Source name')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="source_name"
                  />
                }
              />
              <Field
                component={TextField}
                variant="standard"
                name="external_id"
                label={t('External ID')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="external_id"
                  />
                }
              />
              <Field
                component={TextField}
                variant="standard"
                name="url"
                label={t('URL')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="url" />
                }
              />
              <Field
                component={MarkDownField}
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="description"
                  />
                }
              />
            </Form>
          </div>
        )}
      </Formik>
    );
  }
}

ExternalReferenceEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  externalReference: PropTypes.object,
  context: PropTypes.array,
};

const ExternalReferenceEditionOverview = createFragmentContainer(
  ExternalReferenceEditionOverviewComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceEditionOverview_externalReference on ExternalReference {
        id
        source_name
        url
        external_id
        description
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ExternalReferenceEditionOverview);
