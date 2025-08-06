import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import EmailTemplateForm, { EmailTemplateFormInputKeys, EmailTemplateFormInputs } from '@components/settings/email_template/EmailTemplateForm';
import useEmailTemplateAdd from '@components/settings/email_template/useEmailTemplateAdd';
import useEmailTemplateEdit from '@components/settings/email_template/useEmailTemplateEdit';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';

interface EmailTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  template?: { id: string } & EmailTemplateFormInputs
  updater?: (store: RecordSourceSelectorProxy, rootField: string) => void
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  template,
  updater,
}: EmailTemplateFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  const [commitAddMutation] = useEmailTemplateAdd();
  const [commitEditMutation] = useEmailTemplateEdit();

  const onAdd: FormikConfig<EmailTemplateFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          email_object: values.email_object,
          sender_email: values.sender_email,
          template_body: values.template_body,
        },
      },
      updater: (store) => {
        if (updater) updater(store, 'emailTemplateAdd');
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        onClose();
        if (response.emailTemplateAdd) {
          const { id, entity_type } = response.emailTemplateAdd;
          MESSAGING$.notifySuccess(t_i18n('Email template created'));
          navigate(`${resolveLink(entity_type)}/${id}`);
        }
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  const onEdit = (field: EmailTemplateFormInputKeys, value: unknown) => {
    if (!template) return;

    const input: { key:string, value: [unknown] } = { key: field, value: [value] };
    commitEditMutation({
      variables: { id: template.id, input: [input] },
    });
  };

  return (
    <>
      <Drawer
        title={template ? editionTitle : createTitle}
        open={isOpen}
        onClose={onClose}
      >
        <EmailTemplateForm
          onClose={onClose}
          onSubmit={onAdd}
          onSubmitField={onEdit}
          defaultValues={template}
        />
      </Drawer>
    </>
  );
};

export default FintelTemplateFormDrawer;
