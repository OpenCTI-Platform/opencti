import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import {
  convertCreatedBy,
  convertMarkings,
  convertOrganizations,
  convertStatus,
} from '../../../../utils/Edition';
import Security, {
  KNOWLEDGE_KNUPDATE_KNORGARESTRICT,
} from '../../../../utils/Security';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const campaignMutationFieldPatch = graphql`
  mutation CampaignEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    campaignEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CampaignEditionOverview_campaign
        ...Campaign_campaign
      }
    }
  }
`;

export const campaignEditionOverviewFocus = graphql`
  mutation CampaignEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    campaignEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const campaignMutationRelationAdd = graphql`
  mutation CampaignEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    campaignEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CampaignEditionOverview_campaign
        }
      }
    }
  }
`;

const campaignMutationRelationDelete = graphql`
  mutation CampaignEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    campaignEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CampaignEditionOverview_campaign
      }
    }
  }
`;

const campaignMutationGroupAdd = graphql`
  mutation CampaignEditionOverviewGroupAddMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        ...CampaignEditionOverview_campaign
      }
    }
  }
`;

const campaignMutationGroupDelete = graphql`
  mutation CampaignEditionOverviewGroupDeleteMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        ...CampaignEditionOverview_campaign
      }
    }
  }
`;

const campaignValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

class CampaignEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: campaignEditionOverviewFocus,
      variables: {
        id: this.props.campaign.id,
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
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc(
        'objectOrganization',
        R.pluck('value', values.objectOrganization),
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: campaignMutationFieldPatch,
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
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      campaignValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: campaignMutationFieldPatch,
            variables: {
              id: this.props.campaign.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeObjectOrganization(name, values) {
    const { campaign } = this.props;
    const currentValues = R.pipe(
      R.pathOr([], ['objectOrganization', 'edges']),
      R.map((n) => ({
        label: n.node.name,
        value: n.node.id,
      })),
    )(campaign);
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitMutation({
        mutation: campaignMutationGroupAdd,
        variables: {
          id: this.props.campaign.id,
          organizationId: R.head(added).value,
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: campaignMutationGroupDelete,
        variables: {
          id: this.props.campaign.id,
          organizationId: R.head(removed).value,
        },
      });
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: campaignMutationFieldPatch,
        variables: {
          id: this.props.campaign.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { campaign } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(campaign);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: campaignMutationRelationAdd,
          variables: {
            id: this.props.campaign.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: campaignMutationRelationDelete,
          variables: {
            id: this.props.campaign.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const { t, campaign, context, enableReferences } = this.props;
    const createdBy = convertCreatedBy(campaign);
    const objectMarking = convertMarkings(campaign);
    const objectOrganization = convertOrganizations(campaign);
    const status = convertStatus(t, campaign);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('objectOrganization', objectOrganization),
      R.assoc('x_opencti_workflow_id', status),
      R.pick([
        'name',
        'confidence',
        'description',
        'createdBy',
        'objectMarking',
        'objectOrganization',
        'x_opencti_workflow_id',
      ]),
    )(campaign);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={campaignValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({
          submitForm,
          isSubmitting,
          validateForm,
          setFieldValue,
          values,
        }) => (
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
            <ConfidenceField
              name="confidence"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            <Field
              component={MarkDownField}
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
            {campaign.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Campaign"
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
                id={campaign.id}
              />
            )}
            <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
              <ObjectOrganizationField
                name="objectOrganization"
                style={{ marginTop: 20, width: '100%' }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldname="objectOrganization"
                  />
                }
                onChange={this.handleChangeObjectOrganization.bind(this)}
              />
            </Security>
          </Form>
        )}
      </Formik>
    );
  }
}

CampaignEditionOverviewComponent.propTypes = {
  theme: PropTypes.object,
  t: PropTypes.func,
  campaign: PropTypes.object,
  context: PropTypes.array,
};

const CampaignEditionOverview = createFragmentContainer(
  CampaignEditionOverviewComponent,
  {
    campaign: graphql`
      fragment CampaignEditionOverview_campaign on Campaign {
        id
        name
        confidence
        description
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
        objectOrganization {
          edges {
            node {
              id
              name
            }
          }
        }
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

export default inject18n(CampaignEditionOverview);
