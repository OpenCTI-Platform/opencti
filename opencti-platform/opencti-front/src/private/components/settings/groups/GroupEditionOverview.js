import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import SwitchField from '../../../../components/SwitchField';

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

const groupMutationFieldPatch = graphql`
  mutation GroupEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    groupEdit(id: $id) {
      fieldPatch(input: $input) {
        ...GroupEditionOverview_group
      }
    }
  }
`;

const groupEditionOverviewFocus = graphql`
  mutation GroupEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    groupEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const groupValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  default_assignation: Yup.bool(),
  auto_new_marking: Yup.bool(),
});

class GroupEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: groupEditionOverviewFocus,
      variables: {
        id: this.props.group.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    groupValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: groupMutationFieldPatch,
          variables: { id: this.props.group.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, group, context } = this.props;
    const initialValues = pick(
      ['name', 'description', 'default_assignation', 'auto_new_marking'],
      group,
    );
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={groupValidation(t)}
          onSubmit={() => true}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="name" />
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
              <Field
                component={SwitchField}
                type="checkbox"
                name="default_assignation"
                label={t('Granted by default at user creation')}
                containerstyle={{ marginTop: 20 }}
                onChange={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="default_assignation"
                  />
                }
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="auto_new_marking"
                label={t(
                  'Automatically authorize this group to new marking definition',
                )}
                containerstyle={{ marginTop: 20 }}
                onChange={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="auto_new_marking"
                  />
                }
              />
            </Form>
          )}
        </Formik>
      </div>
    );
  }
}

GroupEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  group: PropTypes.object,
  context: PropTypes.array,
};

const GroupEditionOverview = createFragmentContainer(
  GroupEditionOverviewComponent,
  {
    group: graphql`
      fragment GroupEditionOverview_group on Group {
        id
        name
        description
        default_assignation
        auto_new_marking
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(GroupEditionOverview);
