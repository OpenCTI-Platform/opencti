import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
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

export const observedDataMutationFieldPatch = graphql`
  mutation ObservedDataEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    observedDataEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ObservedDataEditionOverview_observedData
      }
    }
  }
`;

export const observedDataEditionOverviewFocus = graphql`
  mutation ObservedDataEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    observedDataEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const observedDataMutationRelationAdd = graphql`
  mutation ObservedDataEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    observedDataEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ObservedDataEditionOverview_observedData
        }
      }
    }
  }
`;

const observedDataMutationRelationDelete = graphql`
  mutation ObservedDataEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    observedDataEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ObservedDataEditionOverview_observedData
      }
    }
  }
`;

const observedDataValidation = (t) => Yup.object().shape({
  first_observed: Yup.date()
    .required(t('This field is required'))
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_observed: Yup.date()
    .required(t('This field is required'))
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  number_observed: Yup.number().required(t('This field is required')),
  confidence: Yup.number(),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

class ObservedDataEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: observedDataEditionOverviewFocus,
      variables: {
        id: this.props.observedData.id,
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
      R.assoc('first_observed', parse(values.first_observed).format()),
      R.assoc('last_observed', parse(values.last_observed).format()),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    commitMutation({
      mutation: observedDataMutationFieldPatch,
      variables: {
        id: this.props.observedData.id,
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
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      observedDataValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: observedDataMutationFieldPatch,
            variables: {
              id: this.props.observedData.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: observedDataMutationFieldPatch,
        variables: {
          id: this.props.observedData.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { observedData } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(observedData);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: observedDataMutationRelationAdd,
          variables: {
            id: this.props.observedData.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: observedDataMutationRelationDelete,
          variables: {
            id: this.props.observedData.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const { t, observedData, context, enableReferences } = this.props;
    const createdBy = convertCreatedBy(observedData);
    const objectMarking = convertMarkings(observedData);
    const status = convertStatus(t, observedData);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('first_observed', buildDate(observedData.first_observed)),
      R.assoc('last_observed', buildDate(observedData.last_observed)),
      R.assoc('x_opencti_workflow_id', status),
      R.pick([
        'first_observed',
        'last_observed',
        'number_observed',
        'confidence',
        'createdBy',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(observedData);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={observedDataValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm,
          isSubmitting,
          validateForm,
          setFieldValue,
          values,
        }) => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={DateTimePickerField}
                name="first_observed"
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                TextFieldProps={{
                  label: t('First observed'),
                  variant: 'standard',
                  fullWidth: true,
                  helperText: (
                    <SubscriptionFocus
                      context={context}
                      fieldName="first_observed"
                    />
                  ),
                }}
              />
              <Field
                component={DateTimePickerField}
                name="last_observed"
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                TextFieldProps={{
                  label: t('Last observed'),
                  variant: 'standard',
                  fullWidth: true,
                  helperText: (
                    <SubscriptionFocus
                      context={context}
                      fieldName="last_observed"
                    />
                  ),
                }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="number_observed"
                label={t('Number observed')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="number_observed"
                  />
                }
              />
              <ConfidenceField
                name="confidence"
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
                label={t('Confidence')}
                fullWidth={true}
                containerstyle={{ width: '100%', marginTop: 20 }}
                editContext={context}
                variant="edit"
              />
              {observedData.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="Observed-Data"
                  onFocus={this.handleChangeFocus.bind(this)}
                  onChange={this.handleSubmitField.bind(this)}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={context}
                      fieldName="x_opencti_workflow_id"
                    />
                  }
                />
              )}
              <CreatedByField
                name="createdBy"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
                helpertext={
                  <SubscriptionFocus context={context} fieldName="createdBy" />
                }
                onChange={this.handleChangeCreatedBy.bind(this)}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={{ marginTop: 20, width: '100%' }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldname="objectMarking"
                  />
                }
                onChange={this.handleChangeObjectMarking.bind(this)}
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  validateForm={validateForm}
                  setFieldValue={setFieldValue}
                  values={values}
                />
              )}
            </Form>
          </div>
        )}
      </Formik>
    );
  }
}

ObservedDataEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  observedData: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
};

const ObservedDataEditionOverview = createFragmentContainer(
  ObservedDataEditionOverviewComponent,
  {
    observedData: graphql`
      fragment ObservedDataEditionOverview_observedData on ObservedData {
        id
        confidence
        first_observed
        last_observed
        number_observed
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
            }
          }
        }
        is_inferred
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ObservedDataEditionOverview);
