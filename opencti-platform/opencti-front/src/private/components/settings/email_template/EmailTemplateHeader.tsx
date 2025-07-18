import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { Typography, Button } from '@mui/material';
import { useTheme } from '@mui/styles';
import useEmailTemplateEdit from '@components/settings/email_template/useEmailTemplateEdit';
import { useEmailTemplateContext } from '@components/settings/email_template/EmailTemplateContext';
import EmailTemplatePopover from '@components/settings/email_template/EmailTemplatePopover';
import EmailTemplateFormDrawer from '@components/settings/email_template/EmailTemplateFormDrawer';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { Theme } from '../../../../components/Theme';

const headerFragment = graphql`
    fragment EmailTemplateHeader_template on DisseminationList {
        id
        name
        description
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
    { label: t_i18n('Email template'), link: emailTemplateLink },
    { label: template.name },
  ];

  const onSubmit = () => {
    const input = { key: 'template_content', value: [editorValue] };
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
          disabled={editorValue === template.template_content || editOnGoing}
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
        template={{
          id: template.id,
          name: template.name,
          emails: '',
          description: template.description ?? null,
        }}
        onClose={() => setFormOpen(false)}
      />
    </>
  );
};

export default EmailTemplateHeader;
