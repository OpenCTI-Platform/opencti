import { Drawer, SxProps, Toolbar } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateWidgetsSidebar_template$key } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplateWidgetsSidebar_template.graphql';
import useFintelTemplateEdit from '@components/settings/sub_types/fintel_templates/useFintelTemplateEdit';
import { PopoverProps } from '@mui/material/Popover';
import Button from '@mui/material/Button';
import FintelTemplateWidgetsList from '@components/settings/sub_types/fintel_templates/FintelTemplateWidgetsList';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';
import WidgetConfig from '../../../widgets/WidgetConfig';
import type { Widget } from '../../../../../utils/widget/widget';

export const FINTEL_TEMPLATE_SIDEBAR_WIDTH = 350;

const widgetsFragment = graphql`
  fragment FintelTemplateWidgetsSidebar_template on FintelTemplate {
    id
    content
    fintel_template_widgets {
      variable_name
      widget {
        id
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

  const fintelTemplateWidgets = fintelTemplates
    .map((template) => (template.widget.type === 'attribute'
      ? (template.widget.dataSelection[0].columns ?? []).map((c) => ({
        id: template.widget.id,
        variableName: c.variableName,
        type: template.widget.type,
        attribute: c.attribute,
      }))
      : {
        id: template.widget.id,
        variableName: template.variable_name,
        type: template.widget.type,
        filters: template.widget.dataSelection[0].filters,
      }))
    .flat() as { id: string, variableName: string, type: string, filters?: string, attribute?: string }[];
  const usedWidgets = fintelTemplateWidgets.filter((w) => content.includes(`$${w.variableName}`));
  const availableWidgets = fintelTemplateWidgets.filter((w) => !usedWidgets.includes(w));

  const [openedPopover, setOpenedPopover] = useState<string | null>(null);
  const [isWidgetCreationFormOpen, setIsWidgetCreationFormOpen] = useState<boolean>(false);
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);

  const paperStyle: SxProps = {
    '.MuiDrawer-paper': {
      width: FINTEL_TEMPLATE_SIDEBAR_WIDTH,
      padding: theme.spacing(2),
      marginTop: `${settingsMessagesBannerHeight}px`,
    },
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

  const handleUpsertWidget = (widget: Widget) => {
    console.log('widget', widget);
  };
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

  const handleOpenCreateWidget = () => {
    setIsWidgetCreationFormOpen(true);
  };

  return (
    <>
      <Drawer variant="permanent" anchor="right" sx={paperStyle}>
        <Toolbar/>
        <Button
          variant="contained"
          color="primary"
          style={{ float: 'right', width: '100%' }}
          onClick={handleOpenCreateWidget}
        >
          {t_i18n('Create widget')}
        </Button>
        <span style={{ marginTop: 20 }}>{t_i18n('Used template widgets')}</span>
        <FintelTemplateWidgetsList
          widgets={usedWidgets}
          content={content}
          handleWidgetClick={handleWidgetClick}
          openedPopover={openedPopover}
          handleOpenDelete={handleOpenDelete}
          handleOpenPopover={handleOpenPopover}
          handleClosePopover={handleClosePopover}
          anchorEl={anchorEl}
          handleOpenUpdate={handleOpenUpdate}
        />
        <span style={{ marginTop: 20 }}>{t_i18n('Available template widgets')}</span>
        <FintelTemplateWidgetsList
          widgets={availableWidgets}
          content={content}
          handleWidgetClick={handleWidgetClick}
          openedPopover={openedPopover}
          handleOpenDelete={handleOpenDelete}
          handleOpenPopover={handleOpenPopover}
          handleClosePopover={handleClosePopover}
          anchorEl={anchorEl}
          handleOpenUpdate={handleOpenUpdate}
        />
      </Drawer>
      <WidgetConfig
        open={isWidgetCreationFormOpen}
        setOpen={setIsWidgetCreationFormOpen}
        onComplete={handleUpsertWidget}
      />
    </>
  );
};

export default FintelTemplateWidgetsSidebar;
