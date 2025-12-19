import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import withStyles from '@mui/styles/withStyles';
import Button from '@common/button/Button';
import { commitMutation, MESSAGING$ } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import PasswordPolicies from '../../../common/form/PasswordPolicies';

const styles = (theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const userMutationFieldPatch = graphql`
  mutation UserEditionPasswordFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        ...UserEditionPassword_user
      }
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

class UserEditionPasswordComponent extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    const field = { key: 'password', value: values.password };
    commitMutation({
      mutation: userMutationFieldPatch,
      variables: {
        id: this.props.user.id,
        input: field,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess('The password has been updated');
        resetForm();
      },
    });
  }

  render() {
    const { classes, t } = this.props;
    const initialValues = { password: '', confirmation: '' };
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={userValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({ submitForm, isSubmitting }) => (
          <Form style={{ marginTop: this.props.theme.spacing(2) }}>
            <PasswordPolicies style={{ marginBottom: 20 }} />
            <Field
              component={TextField}
              variant="standard"
              name="password"
              label={t('Password')}
              type="password"
              fullWidth={true}
            />
            <Field
              component={TextField}
              variant="standard"
              name="confirmation"
              label={t('Confirmation')}
              type="password"
              fullWidth={true}
              style={{ marginTop: 20 }}
            />
            <div className={classes.buttons}>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Update')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    );
  }
}

UserEditionPasswordComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const UserEditionPassword = createFragmentContainer(
  UserEditionPasswordComponent,
  {
    user: graphql`
      fragment UserEditionPassword_user on User {
        id
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserEditionPassword);
