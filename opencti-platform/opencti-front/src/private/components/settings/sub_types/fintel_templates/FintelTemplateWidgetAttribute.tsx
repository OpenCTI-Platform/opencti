import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import { MoreVert } from '@mui/icons-material';
import React, { MouseEvent } from 'react';
import { Tooltip } from '@mui/material';
import { renderWidgetIcon } from '../../../../../utils/widget/widgetUtils';
import type { Widget } from '../../../../../utils/widget/widget';

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
  return (
    <>
      <Tooltip title={widget.type}>
        {renderWidgetIcon(widget.type, 'small')}
      </Tooltip>
      <ListItemText primary={variableName} />
      <IconButton
        aria-haspopup="true"
        color="primary"
        size="small"
        onClick={(event) => onOpenPopover(event, variableName)}
      >
        <MoreVert />
      </IconButton>
    </>
  );
};

export default FintelTemplateWidgetAttribute;
