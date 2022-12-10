import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import * as R from 'ramda';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { adaptFieldValue } from '../../../../utils/String';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import { RegionEditionOverview_region$key } from './__generated__/RegionEditionOverview_region.graphql';
import CommitMessage from '../../common/form/CommitMessage';

const regionMutationFieldPatch = graphql`
  mutation RegionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    regionEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...RegionEditionOverview_region
        ...Region_region
      }
    }
  }
`;

export const regionEditionOverviewFocus = graphql`
  mutation RegionEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    regionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const regionMutationRelationAdd = graphql`
  mutation RegionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    regionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RegionEditionOverview_region
        }
      }
    }
  }
`;

const regionMutationRelationDelete = graphql`
  mutation RegionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    regionEdit(id: $id) {
      relationDelete(
        toId: $toId,
        relationship_type: $relationship_type
      ) {
        ...RegionEditionOverview_region
      }
    }
  }
`;

const regionEditionOverviewFragment = graphql`
  fragment RegionEditionOverview_region on Region {
    id
    name
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
`;

const regionValidation = (t: (v: string) => string) => Yup.object()
  .shape({
    name: Yup.string()
      .required(t('This field is required')),
    description: Yup.string()
      .min(3, t('The value is too short'))
      .max(5000, t('The value is too long'))
      .required(t('This field is required')),
    x_opencti_workflow_id: Yup.object(),
  });

interface RegionEdititionOverviewProps {
  regionRef: RegionEditionOverview_region$key,
  context: ReadonlyArray<{
    readonly focusOn: string | null;
    readonly name: string;
  } | null> | null
  enableReferences?: boolean
  handleClose: () => void
}

interface RegionEditionFormValues {
  message: string,
  references: Option[],
  x_opencti_workflow_id: Option
  createdBy: Option
  objectMarking: Option[]
}

const RegionEditionOverviewComponent: FunctionComponent<RegionEdititionOverviewProps> = ({
  regionRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const region = useFragment(regionEditionOverviewFragment, regionRef);
  const createdBy = convertCreatedBy(region);
  const objectMarking = convertMarkings(region);
  const status = convertStatus(t, region);

  const [commitRelationAdd] = useMutation(regionMutationRelationAdd);
  const [commitRelationDelete] = useMutation(regionMutationRelationDelete);
  const [commitFieldPatch] = useMutation(regionMutationFieldPatch);
  const [commitEditionFocus] = useMutation(regionEditionOverviewFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: region.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit: FormikConfig<RegionEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitFieldPatch({
      variables: {
        id: region.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleChangeCreatedBy = (_: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: region.id,
          input: { key: 'createdBy', value: [value.value] },
        },
      });
    }
  };

  const handleChangeObjectMarking = (_: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = (region.objectMarking?.edges ?? []).map((n) => ({ label: n?.node.definition, value: n?.node.id }));
      const added = R.difference(values, currentMarkingDefinitions).at(0);
      const removed = R.difference(currentMarkingDefinitions, values).at(0);
      if (added) {
        commitRelationAdd({
          variables: {
            id: region.id,
            input: {
              toId: added.value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed) {
        commitRelationDelete({
          variables: {
            id: region.id,
            toId: removed.value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const handleSubmitField = (name: string, value: Option | string) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      regionValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: region.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
      'description',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(region);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={regionValidation(t)}
      onSubmit={onSubmit}
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
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
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
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          {region.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Region"
              onFocus={handleChangeFocus}
              onChange={handleSubmitField}
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
            onChange={handleChangeCreatedBy}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: 20, width: '100%' }}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            onChange={handleChangeObjectMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting}
              validateForm={validateForm}
              setFieldValue={setFieldValue}
              values={values}
              id={region.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default RegionEditionOverviewComponent;
