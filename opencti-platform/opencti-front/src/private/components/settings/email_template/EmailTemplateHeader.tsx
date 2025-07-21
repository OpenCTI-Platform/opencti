import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { Typography, Button } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import useEmailTemplateEdit from '@components/settings/email_template/useEmailTemplateEdit';
import { useEmailTemplateContext } from '@components/settings/email_template/EmailTemplateContext';
import EmailTemplatePopover from '@components/settings/email_template/EmailTemplatePopover';
import EmailTemplateFormDrawer from '@components/settings/email_template/EmailTemplateFormDrawer';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { EmailTemplateHeader_template$key } from './__generated__/EmailTemplateHeader_template.graphql';

const headerFragment = graphql`
    fragment EmailTemplateHeader_template on EmailTemplate {
        id
        entity_type
        name
        description
        email_object
        sender_email
        template_body
    }
`;

interface EmailTemplateHeaderProps {
  data: EmailTemplateHeader_template$key
}

const EmailTemplateHeader = ({ data }: EmailTemplateHeaderProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [commitEditMutation, editOnGoing] = useEmailTemplateEdit();
  const { editorValue } = useEmailTemplateContext();

  const [isFormOpen, setFormOpen] = useState(false);

  const template = useFragment(headerFragment, data);

  const emailTemplateLink = '/dashboard/settings/accesses/email_templates';
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Security') },
    { label: t_i18n('Email templates'), link: emailTemplateLink },
    { label: template.name },
  ];

  const onSubmit = () => {
    const input = { key: 'template_body', value: [editorValue] };
    commitEditMutation({
      variables: { id: template.id, input: [input] },
    });
  };

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <div style={{ display: 'flex', gap: theme.spacing(1) }}>
        <Typography variant="h1" sx={{ float: 'left' }}>
          {template.name}
        </Typography>

        <Button
          variant="outlined"
          onClick={onSubmit}
          style={{ marginLeft: 'auto' }}
          disabled={editorValue === template.template_body || editOnGoing}
        >
          {t_i18n('Save template')}
        </Button>

        <EmailTemplatePopover
          onUpdate={() => setFormOpen(true)}
          templateId={template.id}
          inline={false}
          onDeleteComplete={() => navigate(emailTemplateLink)}
        />
      </div>

      <EmailTemplateFormDrawer
        isOpen={isFormOpen}
        template={template}
        onClose={() => setFormOpen(false)}
      />
    </>
  );
};

export default EmailTemplateHeader;
