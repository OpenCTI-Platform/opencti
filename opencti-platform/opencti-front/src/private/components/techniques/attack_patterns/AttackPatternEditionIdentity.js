import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, pick, pipe, propOr,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation, WS_ACTIVATED } from '../../../../relay/environment';
import Select from '../../../../components/Select';

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

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionIdentityFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AttackPatternEditionIdentity_attackPattern
      }
    }
  }
`;

export const attackPatternEditionIdentityFocus = graphql`
  mutation AttackPatternEditionIdentityFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        ...AttackPatternEditionIdentity_attackPattern
      }
    }
  }
`;

const attackPatternValidation = () => Yup.object().shape({
  platform: Yup.string(),
  required_permission: Yup.string(),
});

class AttackPatternEditionIdentityComponent extends Component {
  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: attackPatternEditionIdentityFocus,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    attackPatternValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: attackPatternMutationFieldPatch,
          variables: {
            id: this.props.attackPattern.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, attackPattern, editUsers, me,
    } = this.props;
    const initialValues = pipe(
      assoc('platform', propOr([], 'platform', attackPattern)),
      assoc(
        'required_permission',
        propOr([], 'required_permission', attackPattern),
      ),
      pick(['platform', 'required_permission']),
    )(attackPattern);

    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={attackPatternValidation(t)}
          onSubmit={() => true}
          render={() => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="platform"
                  component={Select}
                  multiple={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Platforms')}
                  fullWidth={true}
                  inputProps={{
                    name: 'platform',
                    id: 'platform',
                  }}
                  containerstyle={{ marginTop: 10, width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="platform"
                    />
                  }
                >
                  <MenuItem value="Android">{t('Android')}</MenuItem>
                  <MenuItem value="macOS">{t('macOS')}</MenuItem>
                  <MenuItem value="Linux">{t('Linux')}</MenuItem>
                  <MenuItem value="Windows">{t('Windows')}</MenuItem>
                </Field>
                <Field
                  name="required_permission"
                  component={Select}
                  multiple={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Required permissions')}
                  fullWidth={true}
                  inputProps={{
                    name: 'required_permission',
                    id: 'required_permission',
                  }}
                  containerstyle={{ marginTop: 10, width: '100%' }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="required_permission"
                    />
                  }
                >
                  <MenuItem value="User">User</MenuItem>
                  <MenuItem value="Administrator">Administrator</MenuItem>
                </Field>
              </Form>
            </div>
          )}
        />
      </div>
    );
  }
}

AttackPatternEditionIdentityComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  attackPattern: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const AttackPatternEditionIdentity = createFragmentContainer(
  AttackPatternEditionIdentityComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionIdentity_attackPattern on AttackPattern {
        id
        platform
        required_permission
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(AttackPatternEditionIdentity);
