import { Box, Tab, Tabs } from '@mui/material';
import React, { ReactNode, useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { useEmailTemplateContext } from '@components/settings/email_template/EmailTemplateContext';
import { EmailTemplateTabs_template$key } from '@components/settings/email_template/__generated__/EmailTemplateTabs_template.graphql';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

const tabsFragment = graphql`
    fragment EmailTemplateTabs_template on EmailTemplate {
        template_body
    }
`;

interface ChildrenProps {
  index: number
}

interface EmailTemplateTabsProps {
  data: EmailTemplateTabs_template$key
  children: (props: ChildrenProps) => ReactNode
}

const EmailTemplateTabs = ({ children, data }: EmailTemplateTabsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [index, setIndex] = useState(0);

  const { editorValue, setEditorValue } = useEmailTemplateContext();
  const { template_body } = useFragment(tabsFragment, data);

  useEffect(() => {
    setEditorValue(template_body);
  }, [template_body]);

  return (
    <>
      <Box sx={{
        borderBottom: 1,
        borderColor: 'divider',
        marginBottom: 3,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
      >
        <Tabs value={index} onChange={(_, i) => setIndex(i)}>
          <Tab label={t_i18n('Template Editor')} />
        </Tabs>

        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {editorValue !== template_body ? (
            <span style={{ color: theme.palette.warn.main }}>
              {t_i18n('You have unsaved changes')}
            </span>
          ) : (
            <span style={{ color: theme.palette.common.grey }}>
              {t_i18n('Everything is saved')}
            </span>
          )}
        </div>
      </Box>

      {children({ index })}
    </>
  );
};

export default EmailTemplateTabs;
