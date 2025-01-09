import React, { FunctionComponent, MouseEvent, useMemo, useState } from 'react';
import { AddOutlined } from '@mui/icons-material';
import { Menu, MenuItem, Tooltip, IconButton, List, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import FintelTemplateWidgetDefault from './FintelTemplateWidgetDefault';
import FintelTemplateWidgetAttribute from './FintelTemplateWidgetAttribute';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import type { Widget } from '../../../../../utils/widget/widget';
import { MESSAGING$ } from '../../../../../relay/environment';
import { useFintelTemplateContext } from './FintelTemplateContext';

export interface FintelTemplateWidget {
  variable_name: string
  widget: Widget
}

interface FintelTemplateWidgetsListProps {
  widgets: FintelTemplateWidget[]
  onCreateWidget: () => void
  onDeleteWidget: (w: FintelTemplateWidget) => void
  onUpdateWidget: (w: FintelTemplateWidget) => void
}

const FintelTemplateWidgetsList: FunctionComponent<FintelTemplateWidgetsListProps> = ({
  widgets,
  onCreateWidget,
  onDeleteWidget,
  onUpdateWidget,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { editorValue } = useFintelTemplateContext();

  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const [selectedWidget, setSelectedWidget] = useState<FintelTemplateWidget>();

  const isSelectedWidgetUsed = useMemo(() => {
    if (!selectedWidget) return false;
    return !!editorValue?.includes(`$${selectedWidget.variable_name}`);
  }, [selectedWidget, editorValue]);

  const openPopover = (e: MouseEvent<HTMLButtonElement>, varName: string) => {
    const widget = widgets.find((w) => w.variable_name === varName);
    if (widget) {
      setSelectedWidget(widget);
      setMenuAnchor(e.currentTarget);
    }
  };

  const copyWidgetToClipboard = async () => {
    if (selectedWidget) {
      await navigator.clipboard.writeText(`$${selectedWidget}`);
      MESSAGING$.notifySuccess(t_i18n('Widget copied to clipboard'));
    }
    setMenuAnchor(null);
    setSelectedWidget(undefined);
  };

  const deleteWidget = () => {
    if (selectedWidget) {
      onDeleteWidget(selectedWidget);
    }
    setMenuAnchor(null);
    setSelectedWidget(undefined);
  };

  const updateWidget = () => {
    if (selectedWidget) {
      onUpdateWidget(selectedWidget);
    }
    setMenuAnchor(null);
    setSelectedWidget(undefined);
  };

  return (
    <>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: theme.spacing(4),
        padding: `0 ${theme.spacing(2)}`,
        paddingRight: theme.spacing(1),
      }}
      >
        <Typography variant="body2">
          {t_i18n('Available template widgets')}
        </Typography>

        <Tooltip title={t_i18n('Create widget')}>
          <IconButton
            onClick={onCreateWidget}
            color="primary"
            size="small"
            aria-label={t_i18n('Create widget')}
          >
            <AddOutlined />
          </IconButton>
        </Tooltip>
      </div>

      {widgets.length === 0 && (
        <Typography variant="body2">{t_i18n('No widget')}</Typography>
      )}

      <List>
        {widgets.map((fintelWidget) => {
          const { variable_name, widget } = fintelWidget;
          const isAttributeWidget = widget.type === 'attribute';
          const isSelfAttributeWidget = isAttributeWidget && widget.dataSelection[0].instance_id === 'SELF_ID';

          return isAttributeWidget ? (
            <FintelTemplateWidgetAttribute
              key={variable_name}
              widget={widget}
              onOpenPopover={openPopover}
              variableName={isSelfAttributeWidget
                ? t_i18n('Attributes of the instance')
                : variable_name
              }
            />
          ) : (
            <FintelTemplateWidgetDefault
              key={variable_name}
              widgetType={widget.type}
              variableName={variable_name}
              onOpenPopover={openPopover}
            />
          );
        })}
      </List>

      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={() => setMenuAnchor(null)}
      >
        <MenuItem onClick={copyWidgetToClipboard}>
          {t_i18n('Copy widget to clipboard')}
        </MenuItem>
        <MenuItem onClick={updateWidget}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem
          onClick={deleteWidget}
          disabled={isSelectedWidgetUsed}
        >
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
    </>
  );
};

export default FintelTemplateWidgetsList;
