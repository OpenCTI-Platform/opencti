import React from 'react';
import { ContentCopy, Edit, DeleteOutline, WarningAmber } from '@mui/icons-material';
import { ListItemText, Tooltip, Typography, ListItem } from '@mui/material';
import { IconButton } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import { useFormatter } from '../../../../../components/i18n';
import { useFintelTemplateContext } from './FintelTemplateContext';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';
import type { Widget } from '../../../../../utils/widget/widget';

interface FintelTemplateWidgetDefaultProps {
  widget: Widget;
  variableName: string;
  onUpdate: () => void;
  onDelete: () => void;
}

const FintelTemplateWidgetDefault = ({
  widget,
  variableName,
  onUpdate,
  onDelete,
}: FintelTemplateWidgetDefaultProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { editorValue } = useFintelTemplateContext();
  const isUsed = !!editorValue?.includes(`$${variableName}`);

  const copyWidgetToClipboard = async () => {
    await navigator.clipboard.writeText(`$${variableName}`);
    MESSAGING$.notifySuccess(t_i18n('Widget copied to clipboard'));
  };

  return (
    <ListItem
      key={variableName}
      value={variableName}
      sx={{
        borderBottom: `1px solid ${theme.palette.divider}`,
        paddingRight: 1,
        gap: 0,
        flexDirection: 'column',
        alignItems: 'stretch',
      }}
    >
      <div style={{ display: 'flex', flex: 1, alignItems: 'center', gap: theme.spacing(1) }}>
        <Tooltip title={widget.type}>
          {renderWidgetIcon(widget.type, 'small')}
        </Tooltip>

        <Typography style={{ fontStyle: 'italic', flex: 1 }} variant="body2">
          {widget.parameters?.title ?? variableName}
        </Typography>

        <div>
          <Tooltip title={t_i18n('Change which data to retrieve in this widget')}>
            <IconButton
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Change which data to retrieve in this widget')}
              aria-haspopup="true"
              onClick={onUpdate}
              icon={<Edit fontSize="small" />}
            />
          </Tooltip>

          <Tooltip title={t_i18n('Delete widget')}>
            <IconButton
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Delete widget')}
              aria-haspopup="true"
              onClick={onDelete}
              icon={<DeleteOutline fontSize="small" />}
            />
          </Tooltip>
        </div>
      </div>

      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(1),
        paddingLeft: theme.spacing(3.5),
      }}
      >
        <ListItemText secondary={`$${variableName}`} />

        {!isUsed && (
          <Tooltip title={t_i18n('The widget is not called in the content')}>
            <WarningAmber fontSize="small" color="warning" />
          </Tooltip>
        )}

        <Tooltip title={t_i18n('Copy widget name to clipboard')}>
          <IconButton
            variant="default"
            priority="tertiary"
            aria-label={t_i18n('Copy widget name to clipboard')}
            aria-haspopup="true"
            onClick={copyWidgetToClipboard}
            icon={<ContentCopy fontSize="small" />}
          />
        </Tooltip>
      </div>
    </ListItem>
  );
};

export default FintelTemplateWidgetDefault;
