import IconButton from '@mui/material/IconButton';
import { ContentCopy, MoreVert, WarningAmber } from '@mui/icons-material';
import React, { MouseEvent } from 'react';
import { Tooltip, Typography } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { useTheme } from '@mui/styles';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import { useFormatter } from '../../../../../components/i18n';
import { useFintelTemplateContext } from './FintelTemplateContext';
import type { Theme } from '../../../../../components/Theme';
import { MESSAGING$ } from '../../../../../relay/environment';

interface FintelTemplateWidgetDefaultProps {
  widgetType: string
  variableName: string
  onOpenPopover: (e: MouseEvent<HTMLButtonElement>, varName: string) => void
}

const FintelTemplateWidgetDefault = ({
  widgetType,
  variableName,
  onOpenPopover,
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
        gap: 1,
      }}
    >
      <Tooltip title={widgetType}>
        {renderWidgetIcon(widgetType, 'small')}
      </Tooltip>

      <Typography style={{ flex: 1 }} variant="body2">
        {`$${variableName}`}
      </Typography>

      {!isUsed && (
        <Tooltip title={t_i18n('The widget is not called in the content')}>
          <WarningAmber fontSize="small" color="warning" />
        </Tooltip>
      )}

      <Tooltip style={{ marginRight: -15 }} title={t_i18n('Copy widget to clipboard')}>
        <IconButton
          aria-haspopup="true"
          color="primary"
          onClick={() => copyWidgetToClipboard()}
        >
          <ContentCopy fontSize="small" />
        </IconButton>
      </Tooltip>

      <IconButton
        aria-haspopup="true"
        color="primary"
        size="small"
        onClick={(e) => onOpenPopover(e, variableName)}
      >
        <MoreVert />
      </IconButton>
    </ListItem>
  );
};

export default FintelTemplateWidgetDefault;
