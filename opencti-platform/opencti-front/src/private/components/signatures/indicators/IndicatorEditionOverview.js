import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
  difference,
  head,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import DatePickerField from '../../../../components/DatePickerField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';
import SwitchField from '../../../../components/SwitchField';

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

const indicatorMutationFieldPatch = graphql`
  mutation IndicatorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    indicatorEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IndicatorEditionOverview_indicator
      }
    }
  }
`;

export const indicatorEditionOverviewFocus = graphql`
  mutation IndicatorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    indicatorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const indicatorMutationRelationAdd = graphql`
  mutation IndicatorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    indicatorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IndicatorEditionOverview_indicator
        }
      }
    }
  }
`;

const indicatorMutationRelationDelete = graphql`
  mutation IndicatorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationType: String!
  ) {
    indicatorEdit(id: $id) {
      relationDelete(toId: $toId, relationType: $relationType) {
        ...IndicatorEditionOverview_indicator
      }
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  indicator_pattern: Yup.string().required(t('This field is required')),
  valid_from: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  valid_until: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  score: Yup.number(),
  description: Yup.string(),
  detection: Yup.boolean(),
});

class IndicatorEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: indicatorEditionOverviewFocus,
      variables: {
        id: this.props.indicator.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    indicatorValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: indicatorMutationFieldPatch,
          variables: {
            id: this.props.indicator.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { indicator } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'node', 'name'], indicator),
      value: pathOr(null, ['createdBy', 'node', 'id'], indicator),
      relation: pathOr(null, ['createdBy', 'relation', 'id'], indicator),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: {
          id: this.props.indicator.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          id: this.props.indicator.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: indicatorMutationRelationAdd,
          variables: {
            id: this.props.indicator.id,
            input: {
              fromRole: 'so',
              toId: value.value,
              toRole: 'creator',
              through: 'created_by_ref',
            },
          },
        });
      }
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { indicator } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(indicator);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: {
          id: this.props.indicator.id,
          input: {
            fromRole: 'so',
            toId: head(added).value,
            toRole: 'marking',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          id: this.props.indicator.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, indicator, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'node', 'name'], indicator) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'node', 'name'], indicator),
        value: pathOr(null, ['createdBy', 'node', 'id'], indicator),
        relation: pathOr(null, ['createdBy', 'relation', 'id'], indicator),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(indicator);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'indicator_pattern',
        'description',
        'valid_from',
        'valid_until',
        'score',
        'detection',
        'createdBy',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(indicator);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={indicatorValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
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
              component={TextField}
              name="indicator_pattern"
              label={t('Indicator pattern')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="indicator_pattern"
                />
              }
            />
            <Field
              component={DatePickerField}
              name="valid_from"
              label={t('Valid until')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="valid_from" />
              }
            />
            <Field
              component={DatePickerField}
              name="valid_until"
              label={t('Valid until')}
              invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="valid_until" />
              }
            />
            <Field
              component={TextField}
              name="score"
              label={t('Score')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="score" />
              }
            />
            <Field
              component={TextField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <MarkingDefinitionsField
              name="markingDefinitions"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="markingDefinitions"
                />
              }
              onChange={this.handleChangeMarkingDefinitions.bind(this)}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="detection"
              label={t('Detection')}
              containerstyle={{ marginTop: 20 }}
              onChange={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="negative" />
              }
            />
          </Form>
        )}
      </Formik>
    );
  }
}

IndicatorEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  indicator: PropTypes.object,
  context: PropTypes.array,
};

const IndicatorEditionOverview = createFragmentContainer(
  IndicatorEditionOverviewComponent,
  {
    indicator: graphql`
      fragment IndicatorEditionOverview_indicator on Indicator {
        id
        name
        indicator_pattern
        valid_from
        valid_until
        score
        description
        detection
        createdBy {
          node {
            id
            name
          }
          relation {
            id
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
              definition_type
            }

          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IndicatorEditionOverview);
