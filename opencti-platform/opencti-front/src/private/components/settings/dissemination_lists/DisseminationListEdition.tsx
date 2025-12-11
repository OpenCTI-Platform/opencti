import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { FormikConfig } from 'formik';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import { formatEmailsForApi, formatEmailsForFront } from '@components/settings/dissemination_lists/DisseminationListUtils';
import DisseminationListForm, { DisseminationListFormData, DisseminationListFormInputKeys } from '@components/settings/dissemination_lists/DisseminationListForm';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';

export const disseminationListMutationFieldPatch = graphql`
  mutation DisseminationListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    disseminationListFieldPatch(id: $id, input: $input) {
      ...DisseminationListsLine_node
    }
  }
`;

interface DisseminationListEditionComponentProps {
  data: DisseminationListsLine_node$data;
  isOpen: boolean;
  onClose: () => void;
}

export interface DisseminationListEditionFormData {
  name: string;
  emails: string;
  description: string;
}

const DisseminationListEdition: FunctionComponent<DisseminationListEditionComponentProps> = ({
  data,
  isOpen,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const [commitFieldPatch] = useApiMutation(disseminationListMutationFieldPatch);

  const onSubmit: FormikConfig<DisseminationListEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);

    const input = Object.entries(values)
      .map(([key, value]) => {
        if (key === 'emails') {
          return { key, value: formatEmailsForApi(value) };
        }
        return {
          key,
          value,
        };
      });

    commitFieldPatch({
      variables: {
        id: data?.id,
        input,
      },
      onCompleted: () => {
        setSubmitting(false);
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const onSubmitField = (field: DisseminationListFormInputKeys, value: string) => {
    const input = { key: field, value: field === 'emails' ? formatEmailsForApi(value) : [value] };
    commitFieldPatch({
      variables: {
        id: data?.id,
        input,
      },
    });
  };

  const initialValues: DisseminationListFormData = {
    name: data.name,
    emails: formatEmailsForFront(data.emails),
    description: data.description || '',
  };

  return (
    <Drawer
      title={t_i18n('Update a dissemination list')}
      open={isOpen}
      onClose={onClose}
    >
      <DisseminationListForm
        onSubmit={onSubmit}
        onSubmitField={onSubmitField}
        defaultValues={initialValues}
      />
    </Drawer>
  );
};

export default DisseminationListEdition;
