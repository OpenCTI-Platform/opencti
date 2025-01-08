import React, { MouseEvent } from 'react';
import { WarningAmber, ContentCopy, MoreVert } from '@mui/icons-material';
import { Tooltip, IconButton, ListItemText, ListItem } from '@mui/material';
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
  onOpenPopover: (e: MouseEvent<HTMLButtonElement>, varName: string) => void
}

const FintelTemplateWidgetAttribute = ({
  widget,
  variableName,
  onOpenPopover,
}: FintelTemplateWidgetAttributeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const columns = widget.dataSelection[0].columns ?? [];
  const { editorValue } = useFintelTemplateContext();

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

        <ListItemText style={{ fontStyle: 'italic', flex: 1 }} primary={variableName} />

        <IconButton
          aria-haspopup="true"
          color="primary"
          size="small"
          onClick={(event) => onOpenPopover(event, variableName)}
        >
          <MoreVert />
        </IconButton>
      </div>

      <div style={{ paddingLeft: theme.spacing(3.5) }}>
        {columns.map((column) => {
          const isUsed = !!editorValue?.includes(`$${column.variableName}`);
          return (
            <div
              key={column.variableName}
              style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}
            >
              <ListItemText primary={column.variableName} />

              {!isUsed && (
                <Tooltip title={t_i18n('The attribute is not called in the content')}>
                  <WarningAmber fontSize="small" color="warning" />
                </Tooltip>
              )}

              <IconButton
                aria-haspopup="true"
                color="primary"
                size="small"
                onClick={() => copyAttributeToClipboard(column.variableName ?? '')}
              >
                <ContentCopy fontSize="small" />
              </IconButton>
            </div>
          );
        })}
      </div>
    </ListItem>
  );
};

export default FintelTemplateWidgetAttribute;
