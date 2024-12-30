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
import { ExpandLess, ExpandMore, MoreVert } from '@mui/icons-material';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import Chip from '@mui/material/Chip';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';
import FilterIconButton from '../../../../../components/FilterIconButton';
import FieldOrEmpty from '../../../../../components/FieldOrEmpty';
import { emptyFilterGroup } from '../../../../../utils/filters/filtersUtils';

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

  const availableWidgets = fintelTemplates
    .map((template) => (template.widget.type === 'attribute'
      ? (template.widget.dataSelection[0].columns ?? []).map((c) => ({
        variableName: c.variableName,
        type: template.widget.type,
        attribute: c.attribute,
      }))
      : {
        variableName: template.variable_name,
        type: template.widget.type,
        filters: template.widget.dataSelection[0].filters,
      }))
    .flat() as { variableName: string, type: string, filters?: string, attribute?: string }[];
  const [expandedLines, setExpandedLines] = useState<Record<string, boolean>>({});
  const [openedPopover, setOpenedPopover] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);

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

  const handleOpenPopover = (event: React.SyntheticEvent, lineKey: string) => {
    setAnchorEl(event.currentTarget);
    setOpenedPopover(lineKey);
  };

  const handleClosePopover = () => {
    setAnchorEl(null);
    setOpenedPopover(null);
  };

  const handleOpenUpdate = () => {
    handleClosePopover();
  };

  const handleOpenDelete = () => {
    handleClosePopover();
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
        {availableWidgets.map((widget) => {
          const { variableName } = widget;
          const isChecked = content.includes(`${variableName}`);
          const isNotExpanded = expandedLines[variableName] === undefined || expandedLines[variableName] === false;
          return (
            <>
              <ListItem
                key={id}
                value={variableName}
                style={{ marginLeft: -25, marginBottom: -10 }}
              >
                <Checkbox
                  size="small"
                  checked={isChecked}
                  onClick={() => handleWidgetClick(variableName)}
                />
                <ListItemText primary={variableName}/>
                <ListItemSecondaryAction>
                  <IconButton
                    aria-haspopup="true"
                    size="medium"
                    onClick={() => handleToggleLine(variableName)}
                  >
                    {isNotExpanded
                      ? (<ExpandMore />)
                      : (<ExpandLess />)
                    }
                  </IconButton>
                  <IconButton
                    aria-haspopup="true"
                    color="primary"
                    size="small"
                    onClick={(event) => handleOpenPopover(event, variableName)}
                  >
                    <MoreVert />
                  </IconButton>
                  <Menu
                    anchorEl={anchorEl}
                    open={openedPopover === variableName}
                    onClose={handleClosePopover}
                  >
                    <MenuItem onClick={handleOpenUpdate}>
                      {t_i18n('Update')}
                    </MenuItem>
                    <MenuItem disabled={isChecked} onClick={handleOpenDelete}>
                      {t_i18n('Delete')}
                    </MenuItem>
                  </Menu>
                </ListItemSecondaryAction>
              </ListItem>
              <Collapse
                in={!isNotExpanded}
              >
                <div style={{ marginLeft: 30 }}>
                  {`${t_i18n('Type')}: `}
                  <Chip
                    label={t_i18n(widget.type).toUpperCase()}
                  />
                  {widget.type === 'attribute'
                    ? <div>
                      {`${t_i18n('Attribute')}: `}
                      {widget.attribute}
                    </div>
                    : <div>
                      {`${t_i18n('Filters')}: `}
                      <FieldOrEmpty source={widget.filters}>
                        <FilterIconButton filters={widget.filters ? JSON.parse(widget.filters) : emptyFilterGroup}/>
                      </FieldOrEmpty>
                    </div>
                  }
                </div>
              </Collapse>
            </>
          );
        })}
      </List>
    </Drawer>
  );
};

export default FintelTemplateWidgetsSidebar;
