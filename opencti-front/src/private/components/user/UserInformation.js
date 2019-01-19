import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import TextField from '../../../components/TextField';
import inject18n from '../../../components/i18n';

class UserInformationComponent extends Component {
  render() {
    const { me } = this.props;
    return (
      <div>
        <Typography variant='h1' gutterBottom={true}>
          <T>Profile</T>
        </Typography>
        <Formik
          initialValues={{
            name: '', description: '', marking_definitions: [], killchain_phases: [],
          }}
          validationSchema={malwareValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
          render={({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field name='name' component={TextField} label={t('Name')} fullWidth={true} onChange={this.handleChangeName.bind(this)}/>
                <Field name='description' component={TextField} label={t('Description')}
                       fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }} onChange={this.handleChangeDescription.bind(this)}/>
                <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                  {t('Update')}
                </Button>
              </Form>
          )}
        />
      </div>
    );
  }
}

UserInformationComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
};

const UserInformationFragment = createFragmentContainer(UserInformationComponent, {
  me: graphql`
      fragment UserInformation_me on User {
          name,
          firstname,
          lastname,
          email,
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(UserInformationFragment);
