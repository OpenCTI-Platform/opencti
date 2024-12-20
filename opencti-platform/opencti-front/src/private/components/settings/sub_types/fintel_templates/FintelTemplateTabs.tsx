import { Box, Tab, Tabs, Button, Tooltip } from '@mui/material';
import React, { Dispatch, ReactNode, SetStateAction, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Save } from '@mui/icons-material';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import { useFormatter } from '../../../../../components/i18n';
import { FintelTemplateTabs_template$key } from './__generated__/FintelTemplateTabs_template.graphql';
import type { Theme } from '../../../../../components/Theme';
import { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';

const tabsFragment = graphql`
  fragment FintelTemplateTabs_template on FintelTemplate {
    id
    content
  }
`;

interface ChildrenProps {
  index: number
  editorValue: string
  setEditorValue: Dispatch<SetStateAction<string>>
}

interface FintelTemplateTabsProps {
  data: FintelTemplateTabs_template$key
  children: (props: ChildrenProps) => ReactNode
}

const FintelTemplateTabs = ({ children, data }: FintelTemplateTabsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [index, setIndex] = useState(0);

  const { content, id } = useFragment(tabsFragment, data);
  const [editorValue, setEditorValue] = useState(content);

  const [commitEditMutation, editOnGoing] = useFintelTemplateEdit();

  const onSubmit = () => {
    const input = { key: 'content', value: [editorValue] };
    commitEditMutation({
      variables: { id, input: [input] },
    });
  };

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
            <Tab label={t_i18n('Content Editor')} />
          </Tabs>
        )}
        >
          <Tabs value={index} onChange={(_, i) => setIndex(i)}>
            <Tab label={t_i18n('Content Editor')} />
            <Tab label={t_i18n('Content Preview')} />
          </Tabs>
        </Security>

        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {editorValue !== content && (
            <span style={{ color: theme.palette.warn.main }}>
              {t_i18n('You have unsaved changes')}
            </span>
          )}
          <Tooltip title={t_i18n('Save changes')}>
            <div>
              <Button
                variant="outlined"
                className="icon-outlined"
                onClick={onSubmit}
                disabled={editorValue === content || editOnGoing}
              >
                <Save fontSize="small" />
              </Button>
            </div>
          </Tooltip>
        </div>
      </Box>

      {children({ index, setEditorValue, editorValue })}
    </>
  );
};

export default FintelTemplateTabs;
