import { Box, Tab, Tabs } from '@mui/material';
import React, { ReactNode, useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { useFintelTemplateContext } from '@components/settings/sub_types/fintel_templates/FintelTemplateContext';
import { useFormatter } from '../../../../../components/i18n';
import { FintelTemplateTabs_template$key } from './__generated__/FintelTemplateTabs_template.graphql';
import type { Theme } from '../../../../../components/Theme';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';

const tabsFragment = graphql`
  fragment FintelTemplateTabs_template on FintelTemplate {
    template_content
  }
`;

interface ChildrenProps {
  index: number
}

interface FintelTemplateTabsProps {
  data: FintelTemplateTabs_template$key
  children: (props: ChildrenProps) => ReactNode
}

const FintelTemplateTabs = ({ children, data }: FintelTemplateTabsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [index, setIndex] = useState(0);

  const { editorValue, setEditorValue } = useFintelTemplateContext();
  const { template_content } = useFragment(tabsFragment, data);

  useEffect(() => {
    setEditorValue(template_content);
  }, [template_content]);

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
        <Security needs={[KNOWLEDGE]} placeholder={(
          <Tabs value={index} onChange={(_, i) => setIndex(i)}>
            <Tab label={t_i18n('Template Editor')} />
          </Tabs>
        )}
        >
          <Tabs value={index} onChange={(_, i) => setIndex(i)}>
            <Tab label={t_i18n('Template Editor')} />
            <Tab label={t_i18n('Template Preview')} />
          </Tabs>
        </Security>

        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {editorValue !== template_content ? (
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

export default FintelTemplateTabs;
