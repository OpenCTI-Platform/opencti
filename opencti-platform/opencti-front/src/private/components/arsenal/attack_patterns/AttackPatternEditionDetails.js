import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { assoc, compose, pick, pipe, propOr } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import SelectField from '../../../../components/SelectField';
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

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AttackPatternEditionDetails_attackPattern
        ...AttackPattern_attackPattern
      }
    }
  }
`;

export const attackPatternEditionDetailsFocus = graphql`
  mutation AttackPatternEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const attackPatternValidation = () => Yup.object().shape({
  x_mitre_id: Yup.string().nullable(),
  x_mitre_platforms: Yup.array(),
  x_mitre_permissions_required: Yup.array(),
  x_mitre_detection: Yup.string().nullable(),
});

class AttackPatternEditionDetailsComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: attackPatternEditionDetailsFocus,
      variables: {
        id: this.props.attackPattern.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    attackPatternValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: attackPatternMutationFieldPatch,
          variables: {
            id: this.props.attackPattern.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, attackPattern, context } = this.props;
    const initialValues = pipe(
      assoc(
        'x_mitre_platforms',
        propOr([], 'x_mitre_platforms', attackPattern),
      ),
      assoc(
        'x_mitre_permissions_required',
        propOr([], 'x_mitre_permissions_required', attackPattern),
      ),
      assoc(
        'x_mitre_detection',
        propOr('', 'x_mitre_detection', attackPattern),
      ),
      pick([
        'x_mitre_id',
        'x_mitre_platforms',
        'x_mitre_permissions_required',
        'x_mitre_detection',
      ]),
    )(attackPattern);

    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={attackPatternValidation()}
        onSubmit={() => true}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="x_mitre_id"
              label={t('External ID')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="x_mitre_id" />
              }
            />
            <Field
              component={SelectField}
              variant="standard"
              name="x_mitre_platforms"
              multiple={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Platforms')}
              fullWidth={true}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_mitre_platforms"
                />
              }
            >
              <MenuItem value="Android">{t('Android')}</MenuItem>
              <MenuItem value="macOS">{t('macOS')}</MenuItem>
              <MenuItem value="Linux">{t('Linux')}</MenuItem>
              <MenuItem value="Windows">{t('Windows')}</MenuItem>
            </Field>
            <Field
              component={SelectField}
              variant="standard"
              name="x_mitre_permissions_required"
              multiple={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Required permissions')}
              fullWidth={true}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_mitre_permissions_required"
                />
              }
            >
              <MenuItem value="User">User</MenuItem>
              <MenuItem value="Administrator">Administrator</MenuItem>
            </Field>
            <Field
              component={TextField}
              variant="standard"
              name="x_mitre_detection"
              label={t('Detection')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_mitre_detection"
                />
              }
            />
          </Form>
        )}
      </Formik>
    );
  }
}

AttackPatternEditionDetailsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  attackPattern: PropTypes.object,
  context: PropTypes.array,
};

const AttackPatternEditionDetails = createFragmentContainer(
  AttackPatternEditionDetailsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionDetails_attackPattern on AttackPattern {
        id
        x_mitre_platforms
        x_mitre_permissions_required
        x_mitre_id
        x_mitre_detection
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(AttackPatternEditionDetails);
