import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { Option } from '../../common/form/ReferenceField';
import { adaptFieldValue } from '../../../../utils/String';
import { CaseEditionOverview_case$key } from './__generated__/CaseEditionOverview_case.graphql';

const caseMutationFieldPatch = graphql`
  mutation CaseEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    caseFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...CaseEditionOverview_case
      ...Case_case
    }
  }
`;

export const caseEditionOverviewFocus = graphql`
  mutation CaseEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    caseContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const caseEditionOverviewFragment = graphql`
  fragment CaseEditionOverview_case on Case {
    id
    name
    description
    rating
    creator {
      id
      name
    }
    x_opencti_stix_ids
    createdBy {
      ... on Identity {
        id
        name
        entity_type
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

const caseValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  rating: Yup.number(),
});

interface CaseEditionOverviewProps {
  caseRef: CaseEditionOverview_case$key,
  context: ReadonlyArray<{
    readonly focusOn: string | null;
    readonly name: string;
  } | null> | null
  enableReferences?: boolean
  handleClose: () => void
}

interface CaseEditionFormValues {
  x_opencti_workflow_id: string | { label: string, color: string, value: string, order: string }
}

const CaseEditionOverviewComponent: FunctionComponent<CaseEditionOverviewProps> = ({
  caseRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const caseData = useFragment(caseEditionOverviewFragment, caseRef);

  const status = convertStatus(t, caseData);

  const [commitFieldPatch] = useMutation(caseMutationFieldPatch);
  const [commitEditionFocus] = useMutation(caseEditionOverviewFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: caseData.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit: FormikConfig<CaseEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const inputValues = Object.entries({
      x_opencti_workflow_id: values.x_opencti_workflow_id,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    commitFieldPatch({
      variables: {
        id: caseData.id,
        input: inputValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: Option | string | string[]) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      caseValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: caseData.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: caseData.name,
    description: caseData.description,
    rating: caseData.rating,
    status,
    x_opencti_workflow_id: caseData.x_opencti_stix_ids,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={caseValidation(t)}
      onSubmit={onSubmit}
    >
      {({
        setFieldValue,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          {caseData?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Workflow Feedback"
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
        </Form>
      )}
    </Formik>
  );
};

export default CaseEditionOverviewComponent;
