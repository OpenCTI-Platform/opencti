import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Button from '@mui/material/Button';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import { buildDate } from '../../../../utils/Time';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
  requestSubscription,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import {
  SubscriptionAvatars,
  SubscriptionFocus,
} from '../../../../components/Subscription';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ConfidenceField from '../../common/form/ConfidenceField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  button: {
    float: 'right',
    backgroundColor: '#f44336',
    borderColor: '#f44336',
    color: '#ffffff',
    '&:hover': {
      backgroundColor: '#c62828',
      borderColor: '#c62828',
    },
  },
  buttonLeft: {
    float: 'left',
  },
});

const subscription = graphql`
  subscription StixSightingRelationshipEditionOverviewSubscription($id: ID!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipEditionOverview_stixSightingRelationship
    }
  }
`;

const stixSightingRelationshipMutationFieldPatch = graphql`
  mutation StixSightingRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixSightingRelationshipEditionOverview_stixSightingRelationship
      }
    }
  }
`;

export const stixSightingRelationshipEditionFocus = graphql`
  mutation StixSightingRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixSightingRelationshipMutationRelationAdd = graphql`
  mutation StixSightingRelationshipEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixSightingRelationshipEditionOverview_stixSightingRelationship
        }
      }
    }
  }
`;

const stixSightingRelationshipMutationRelationDelete = graphql`
  mutation StixSightingRelationshipEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixSightingRelationshipEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixSightingRelationshipEditionOverview_stixSightingRelationship
      }
    }
  }
`;

const stixSightingRelationshipValidation = (t) => Yup.object().shape({
  attribute_count: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  last_seen: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  description: Yup.string().nullable(),
  x_opencti_negative: Yup.boolean(),
  x_opencti_workflow_id: Yup.object(),
});

const StixSightingRelationshipEditionContainer = ({
  t,
  classes,
  handleClose,
  handleDelete,
  stixSightingRelationship,
  stixDomainObject,
  inferred,
}) => {
  const { editContext } = stixSightingRelationship;
  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: stixSightingRelationship.id,
      },
    });
    return () => {
      sub.dispose();
    };
  });
  const handleChangeObjectMarking = (name, values) => {
    const currentMarkingDefinitions = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(stixSightingRelationship);
    const added = R.difference(values, currentMarkingDefinitions);
    const removed = R.difference(currentMarkingDefinitions, values);
    if (added.length > 0) {
      commitMutation({
        mutation: stixSightingRelationshipMutationRelationAdd,
        variables: {
          id: stixSightingRelationship.id,
          input: {
            toId: R.head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: stixSightingRelationshipMutationRelationDelete,
        variables: {
          id: stixSightingRelationship.id,
          toId: R.head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    commitMutation({
      mutation: stixSightingRelationshipMutationFieldPatch,
      variables: {
        id: stixSightingRelationship.id,
        input: { key: 'createdBy', value: value.value || '' },
      },
    });
  };
  const handleChangeFocus = (name) => {
    commitMutation({
      mutation: stixSightingRelationshipEditionFocus,
      variables: {
        id: stixSightingRelationship.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name, value) => {
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    stixSightingRelationshipValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixSightingRelationshipMutationFieldPatch,
          variables: {
            id: stixSightingRelationship.id,
            input: { key: name, value: finalValue || '' },
          },
        });
      })
      .catch(() => false);
  };
  const createdBy = convertCreatedBy(stixSightingRelationship);
  const objectMarking = convertMarkings(stixSightingRelationship);
  const status = convertStatus(t, stixSightingRelationship);
  const initialValues = R.pipe(
    R.assoc('first_seen', buildDate(stixSightingRelationship.first_seen)),
    R.assoc('last_seen', buildDate(stixSightingRelationship.last_seen)),
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'attribute_count',
      'confidence',
      'first_seen',
      'last_seen',
      'description',
      'x_opencti_negative',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(stixSightingRelationship);
  const link = stixDomainObject
    ? resolveLink(stixDomainObject.entity_type)
    : '';
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a sighting')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixSightingRelationshipValidation(t)}
        >
          {(setFieldValue) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="attribute_count"
                label={t('Count')}
                fullWidth={true}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="attribute_count"
                  />
                }
                disabled={inferred}
              />
              <ConfidenceField
                variant="edit"
                name="confidence"
                label={t('Confidence level')}
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                editContext={editContext}
                containerstyle={{ marginTop: 20, width: '100%' }}
                disabled={inferred}
              />
              <Field
                component={DateTimePickerField}
                name="first_seen"
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                TextFieldProps={{
                  label: t('First seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="first_seen"
                    />
                  ),
                }}
                disabled={inferred}
              />
              <Field
                component={DateTimePickerField}
                name="last_seen"
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                TextFieldProps={{
                  label: t('Last seen'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="last_seen"
                    />
                  ),
                }}
                disabled={inferred}
              />
              <Field
                component={MarkDownField}
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="description"
                  />
                }
                disabled={inferred}
              />
              {stixSightingRelationship.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="stix-sighting-relationship"
                  onFocus={handleChangeFocus}
                  onChange={handleSubmitField}
                  setFieldValue={setFieldValue}
                  style={{ marginTop: 20 }}
                  helpertext={
                    <SubscriptionFocus
                      context={editContext}
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
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="createdBy"
                  />
                }
                disabled={inferred}
                onChange={handleChangeCreatedBy}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={{ marginTop: 20, width: '100%' }}
                helpertext={
                  <SubscriptionFocus
                    context={editContext}
                    fieldname="objectMarking"
                  />
                }
                disabled={inferred}
                onChange={handleChangeObjectMarking}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="x_opencti_negative"
                label={t('False positive')}
                containerstyle={{ marginTop: 20 }}
                onChange={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={editContext}
                    fieldName="x_opencti_negative"
                  />
                }
                disabled={inferred}
              />
            </Form>
          )}
        </Formik>
        {stixDomainObject && (
          <Button
            variant="contained"
            color="primary"
            component={Link}
            to={`${link}/${stixDomainObject.id}/knowledge/relations/${stixSightingRelationship.id}`}
            classes={{ root: classes.buttonLeft }}
          >
            {t('Details')}
          </Button>
        )}
        {typeof handleDelete === 'function' && (
          <Button
            variant="contained"
            onClick={() => handleDelete()}
            classes={{ root: classes.button }}
            disabled={inferred}
          >
            {t('Delete')}
          </Button>
        )}
        <div className="clearfix" />
      </div>
    </div>
  );
};

StixSightingRelationshipEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  stixDomainObject: PropTypes.object,
  stixSightingRelationship: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  inferred: PropTypes.bool,
  noStoreUpdate: PropTypes.bool,
};

const StixSightingRelationshipEditionFragment = createFragmentContainer(
  StixSightingRelationshipEditionContainer,
  {
    stixSightingRelationship: graphql`
      fragment StixSightingRelationshipEditionOverview_stixSightingRelationship on StixSightingRelationship {
        id
        attribute_count
        x_opencti_negative
        confidence
        first_seen
        last_seen
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
        editContext {
          name
          focusOn
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

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixSightingRelationshipEditionFragment);
