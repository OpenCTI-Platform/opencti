import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, MoreVert } from '@mui/icons-material';
import React, { FunctionComponent, MouseEvent } from 'react';
import { renderWidgetIcon } from '@components/widgets/widgetUtils';
import { Tooltip } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface FintelTemplateWidgetsListProps {
  widgets: { id: string, variableName: string, type: string }[],
  handleOpenPopover: (event: MouseEvent<HTMLButtonElement>, lineKey: string) => void,
  title: string;
  onCreateWidget?: () =>void
}

const FintelTemplateWidgetsList: FunctionComponent<FintelTemplateWidgetsListProps> = ({
  widgets,
  handleOpenPopover,
  title,
  onCreateWidget,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <div style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: theme.spacing(4),
        padding: `0 ${theme.spacing(2)}`,
        paddingRight: theme.spacing(1),
      }}
      >
        <Typography variant="body2">{title}</Typography>
        {onCreateWidget && (
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
        )}
      </div>

      {widgets.length === 0 && (
        <Typography variant="body2">{t_i18n('No widget')}</Typography>
      )}

      <List>
        {widgets.map((widget) => {
          const { variableName } = widget;
          return (
            <ListItem
              key={variableName}
              value={variableName}
              sx={{ paddingRight: 1, paddingTop: 0, gap: 2 }}
            >
              {renderWidgetIcon(widget.type, 'small')}
              <ListItemText primary={variableName} />
              <IconButton
                aria-haspopup="true"
                color="primary"
                size="small"
                onClick={(event) => handleOpenPopover(event, variableName)}
              >
                <MoreVert />
              </IconButton>
            </ListItem>
          );
        })}
      </List>
    </div>
  );
};

export default FintelTemplateWidgetsList;
