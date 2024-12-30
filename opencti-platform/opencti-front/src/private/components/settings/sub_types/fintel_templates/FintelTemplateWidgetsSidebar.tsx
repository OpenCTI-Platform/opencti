import { Drawer, SxProps, Toolbar } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateWidgetsSidebar_template$key } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplateWidgetsSidebar_template.graphql';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import useFintelTemplateEdit from '@components/settings/sub_types/fintel_templates/useFintelTemplateEdit';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import IconButton from '@mui/material/IconButton';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';

export const FINTEL_TEMPLATE_SIDEBAR_WIDTH = 350;

const widgetsFragment = graphql`
  fragment FintelTemplateWidgetsSidebar_template on FintelTemplate {
    id
    content
    fintel_template_widgets {
      variable_name
      widget {
        type
        dataSelection {
          perspective
          filters
          columns {
            variableName
            label
            attribute
          }
        }
        parameters {
          title
        }
      }
    }
  }
`;

interface FintelTemplateWidetsSidebarProps {
  data: FintelTemplateWidgetsSidebar_template$key,
}

const FintelTemplateWidgetsSidebar: FunctionComponent<FintelTemplateWidetsSidebarProps> = ({ data }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { id, content, fintel_template_widgets: fintelTemplates } = useFragment(widgetsFragment, data);

  const availableVariableNames = fintelTemplates.map((template) => (template.widget.type === 'attribute'
    ? (template.widget.dataSelection[0].columns ?? []).map((c) => c.variableName)
    : template.variable_name)).flat() as string[];
  const [expandedLines, setExpandedLines] = useState<Record<string, boolean>>({});

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: FINTEL_TEMPLATE_SIDEBAR_WIDTH,
      padding: theme.spacing(2),
      marginTop: `${settingsMessagesBannerHeight}px`,
    },
  };

  const handleToggleLine = (lineKey: string) => {
    setExpandedLines({
      ...expandedLines,
      [lineKey]:
        expandedLines[lineKey] !== undefined
          ? !expandedLines[lineKey]
          : true,
    });
  };

  const [commitEditMutation] = useFintelTemplateEdit();

  const handleWidgetClick = (variableName: string) => {
    const newContent = content.concat(`$${variableName}`);
    const input = { key: 'content', value: [newContent] };
    commitEditMutation({
      variables: { id, input: [input] },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('The widget has been added at the end of your template content.'));
      },
    });
  };

  return (
    <Drawer variant="permanent" anchor="right" sx={paperStyle}>
      <Toolbar />
      {t_i18n('Template widgets')}
      <List>
        {availableVariableNames.map((variableName) => {
          const isNotExpanded = expandedLines[variableName] === undefined || expandedLines[variableName] === false;
          return (
            <>
              <ListItem
                key={id}
                value={variableName}
                dense={true}
              >
                <Checkbox
                  size="small"
                  checked={content.includes(`${variableName}`)}
                  onClick={() => handleWidgetClick(variableName)}
                />
                <ListItemText primary={variableName}/>
                <ListItemSecondaryAction>
                  <IconButton
                    aria-haspopup="true"
                    size="large"
                    onClick={() => handleToggleLine(variableName)}
                  >
                    {isNotExpanded
                      ? (<ExpandMore />)
                      : (<ExpandLess />)
                  }
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
              <Collapse
                in={!isNotExpanded}
              >
                test
              </Collapse>
            </>
          );
        })}
      </List>
    </Drawer>
  );
};

export default FintelTemplateWidgetsSidebar;
