import React from 'react';
import { WarningAmber, ContentCopy, Edit, DeleteOutline } from '@mui/icons-material';
import { Tooltip, IconButton, ListItemText, ListItem, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { useFintelTemplateContext } from './FintelTemplateContext';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import type { Widget } from '../../../../../utils/widget/widget';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';

interface FintelTemplateWidgetAttributeProps {
  widget: Widget
  variableName: string
  onUpdate?: () => void
  onDelete?: () => void
  title?: string
}

const FintelTemplateWidgetAttribute = ({
  widget,
  variableName,
  onUpdate,
  onDelete,
  title,
}: FintelTemplateWidgetAttributeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { editorValue } = useFintelTemplateContext();

  const columns = widget.dataSelection[0].columns ?? [];

  const copyAttributeToClipboard = async (varName: string) => {
    await navigator.clipboard.writeText(`$${varName}`);
    MESSAGING$.notifySuccess(t_i18n('Attribute copied to clipboard'));
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
          {title ?? widget.parameters?.title ?? variableName}
        </Typography>

        <div style={{ height: 36 }}>
          {onUpdate && (
            <Tooltip title={t_i18n('Change which data to retrieve in this widget')}>
              <IconButton
                aria-haspopup="true"
                color="primary"
                onClick={onUpdate}
              >
                <Edit fontSize="small" />
              </IconButton>
            </Tooltip>
          )}

          {onDelete && (
            <Tooltip title={t_i18n('Delete widget')}>
              <IconButton
                aria-haspopup="true"
                color="primary"
                onClick={onDelete}
              >
                <DeleteOutline fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </div>
      </div>

      <div style={{ paddingLeft: theme.spacing(3.5) }}>
        {columns.map((column) => {
          const isUsed = !!editorValue?.includes(`$${column.variableName}`);

          return (
            <div
              key={column.variableName}
              style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}
            >
              <ListItemText secondary={`$${column.variableName} (${column.label})`} />

              {!isUsed && (
                <Tooltip title={t_i18n('The attribute is not called in the content')}>
                  <WarningAmber fontSize="small" color="warning" />
                </Tooltip>
              )}

              <Tooltip title={t_i18n('Copy attribute name to clipboard')}>
                <IconButton
                  aria-haspopup="true"
                  color="primary"
                  onClick={() => copyAttributeToClipboard(column.variableName ?? '')}
                >
                  <ContentCopy fontSize="small" />
                </IconButton>
              </Tooltip>
            </div>
          );
        })}
      </div>
    </ListItem>
  );
};

export default FintelTemplateWidgetAttribute;
