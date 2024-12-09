import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import FintelTemplateForm, { FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';

const fintelTemplateAdd = graphql`
  mutation FintelTemplateFormDrawerAddMutation($input: FintelTemplateAddInput!) {
    fintelTemplateAdd(input: $input) {
      id
      name
      description
      instance_filters
      settings_types
      start_date
    }
  }
`;

interface FintelTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  entityType: string
  template?: FintelTemplateFormInputs
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  template,
}: FintelTemplateFormDrawerProps) => {
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  const [commitAddMutation] = useApiMutation(fintelTemplateAdd);

  const onAdd: FormikConfig<FintelTemplateFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          start_date: values.published ? new Date() : null,
          settings_types: [entityType],
        },
      },
      updater: (store) => {
        // insertNode(
        //   store,
        //   'Pagination_publicDashboards',
        //   paginationOptions,
        //   'publicDashboardAdd',
        // );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onClose();
        MESSAGING$.notifySuccess(t_i18n('Fintel template created'));
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  return (
    <Drawer
      title={template ? editionTitle : createTitle}
      open={isOpen}
      onClose={onClose}
    >
      <FintelTemplateForm
        onClose={onClose}
        onSubmit={onAdd}
        onSubmitField={console.log}
        isEdition={!!template}
        defaultValues={template}
      />
    </Drawer>
  );
};

export default FintelTemplateFormDrawer;
