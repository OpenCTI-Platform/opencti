import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import { MoreVert, WarningAmber } from '@mui/icons-material';
import React, { MouseEvent } from 'react';
import { Tooltip } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { useTheme } from '@mui/styles';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import { useFormatter } from '../../../../../components/i18n';
import { useFintelTemplateContext } from './FintelTemplateContext';
import type { Theme } from '../../../../../components/Theme';

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

      <ListItemText primary={variableName} />

      {!isUsed && (
        <Tooltip title={t_i18n('The widget is not called in the content')}>
          <WarningAmber fontSize="small" color="warning" />
        </Tooltip>
      )}

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
