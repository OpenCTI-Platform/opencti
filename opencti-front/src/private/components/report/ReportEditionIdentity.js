import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, pick, pipe,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../components/i18n';
import DatePickerField from '../../../components/DatePickerField';
import Select from '../../../components/Select';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, WS_ACTIVATED } from '../../../relay/environment';
import { dateFormat } from '../../../utils/Time';

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

const reportMutationFieldPatch = graphql`
  mutation ReportEditionIdentityFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ReportEditionIdentity_report
      }
    }
  }
`;

const reportEditionIdentityFocus = graphql`
  mutation ReportEditionIdentityFocusMutation($id: ID!, $input: EditContext!) {
    reportEdit(id: $id) {
      contextPatch(input: $input) {
        ...ReportEditionIdentity_report
      }
    }
  }
`;

const reportValidation = t => Yup.object().shape({
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  object_status: Yup.number(),
  source_confidence_level: Yup.number(),
});

class ReportEditionIdentityComponent extends Component {
  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: reportEditionIdentityFocus,
        variables: {
          id: this.props.report.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    reportValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: reportMutationFieldPatch,
          variables: {
            id: this.props.report.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, report, editUsers, me,
    } = this.props;
    const initialValues = pipe(
      assoc('published', dateFormat(report.published)),
      pick(['published', 'object_status', 'source_confidence_level']),
    )(report);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={reportValidation(t)}
          onSubmit={() => true}
          render={() => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="published"
                  component={DatePickerField}
                  label={t('Publication date')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="published"
                    />
                  }
                />
                <Field
                  name="object_status"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Processing status')}
                  fullWidth={true}
                  inputProps={{
                    name: 'object_status',
                    id: 'object_status',
                  }}
                  containerstyle={{ width: '100%', marginTop: 10 }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="object_status"
                    />
                  }
                >
                  <MenuItem key="0" value="0">
                    {t('report_status_0')}
                  </MenuItem>
                  <MenuItem key="1" value="1">
                    {t('report_status_1')}
                  </MenuItem>
                  <MenuItem key="2" value="2">
                    {t('report_status_2')}
                  </MenuItem>
                  <MenuItem key="3" value="3">
                    {t('report_status_3')}
                  </MenuItem>
                </Field>
                <Field
                  name="source_confidence_level"
                  component={Select}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  label={t('Confidence level')}
                  fullWidth={true}
                  inputProps={{
                    name: 'source_confidence_level',
                    id: 'source_confidence_level',
                  }}
                  containerstyle={{ width: '100%', marginTop: 10 }}
                  helpertext={
                    <SubscriptionFocus
                      me={me}
                      users={editUsers}
                      fieldName="source_confidence_level"
                    />
                  }
                >
                  <MenuItem key="1" value="1">
                    {t('confidence_1')}
                  </MenuItem>
                  <MenuItem key="2" value="2">
                    {t('confidence_2')}
                  </MenuItem>
                  <MenuItem key="3" value="3">
                    {t('confidence_3')}
                  </MenuItem>
                  <MenuItem key="4" value="4">
                    {t('confidence_4')}
                  </MenuItem>
                  <MenuItem key="5" value="5">
                    {t('confidence_5')}
                  </MenuItem>
                </Field>
              </Form>
            </div>
          )}
        />
      </div>
    );
  }
}

ReportEditionIdentityComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  report: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const ReportEditionIdentity = createFragmentContainer(
  ReportEditionIdentityComponent,
  {
    report: graphql`
      fragment ReportEditionIdentity_report on Report {
        id
        published
        object_status
        source_confidence_level
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportEditionIdentity);
