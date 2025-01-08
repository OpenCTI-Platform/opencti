import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import { MoreVert, WarningAmber } from '@mui/icons-material';
import React, { MouseEvent } from 'react';
import { Tooltip } from '@mui/material';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import { useFormatter } from '../../../../../components/i18n';
import { useFintelTemplateContext } from './FintelTemplateContext';

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
  const { t_i18n } = useFormatter();
  const { editorValue } = useFintelTemplateContext();
  const isUsed = !!editorValue?.includes(`$${variableName}`);

  return (
    <>
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
    </>
  );
};

export default FintelTemplateWidgetDefault;
