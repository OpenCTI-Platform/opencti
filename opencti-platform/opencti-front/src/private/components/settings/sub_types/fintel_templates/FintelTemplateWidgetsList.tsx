import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { MoreVert, AddOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import React, { FunctionComponent } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import { renderWidgetIcon } from '@components/widgets/widgetUtils';
import { Tooltip } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';

interface FintelTemplateWidgetsListProps {
  widgets: { id: string, variableName: string, type: string, filters?: string, attribute?: string }[],
  handleAddWidget: (variableName: string) => void,
  openedPopover: string | null,
  handleOpenDelete?: () => void,
  handleOpenPopover: (event: React.SyntheticEvent, lineKey: string) => void,
  handleClosePopover: () => void,
  anchorEl: PopoverProps['anchorEl'],
  handleOpenUpdate: () => void,
}

const FintelTemplateWidgetsList: FunctionComponent<FintelTemplateWidgetsListProps> = ({
  widgets,
  handleAddWidget,
  openedPopover,
  handleOpenDelete,
  handleOpenPopover,
  handleClosePopover,
  anchorEl,
  handleOpenUpdate,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <List>
      {widgets.map((widget) => {
        const { variableName } = widget;
        return (
          <>
            <ListItem
              key={widget.id}
              value={variableName}
              style={{ marginLeft: -25, marginBottom: -10 }}
            >
              {renderWidgetIcon(widget.type, 'medium')}
              <ListItemText style={{ marginLeft: 5 }} primary={variableName}/>
              <ListItemSecondaryAction>
                <Tooltip
                  title={t_i18n('Add the widget at the end of the content')}
                >
                  <IconButton
                    onClick={() => handleAddWidget(variableName)}
                    color="primary"
                    size="small"
                    aria-label={t_i18n('Add a widget')}
                  >
                    <AddOutlined />
                  </IconButton>
                </Tooltip>
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
                  {handleOpenDelete && <MenuItem onClick={handleOpenDelete}>
                    {t_i18n('Delete')}
                  </MenuItem>}
                </Menu>
              </ListItemSecondaryAction>
            </ListItem>
          </>
        );
      })}
    </List>
  );
};

export default FintelTemplateWidgetsList;
