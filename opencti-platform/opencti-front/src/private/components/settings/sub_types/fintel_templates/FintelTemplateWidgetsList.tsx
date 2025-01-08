import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import IconButton from '@mui/material/IconButton';
import { AddOutlined } from '@mui/icons-material';
import React, { FunctionComponent, MouseEvent } from 'react';
import { Tooltip } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import FintelTemplateWidgetDefault from './FintelTemplateWidgetDefault';
import FintelTemplateWidgetAttribute from './FintelTemplateWidgetAttribute';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import type { Widget } from '../../../../../utils/widget/widget';

export interface FintelTemplateWidget {
  variable_name: string
  widget: Widget
}

interface FintelTemplateWidgetsListProps {
  widgets: FintelTemplateWidget[]
  handleOpenPopover: (event: MouseEvent<HTMLButtonElement>, lineKey: string) => void
  title: string
  onCreateWidget?: () => void
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
        {widgets.map((fintelWidget) => {
          const { variable_name, widget } = fintelWidget;
          const isAttributeWidget = widget.type === 'attribute';
          const isSelfAttributeWidget = isAttributeWidget && widget.dataSelection[0].instance_id === 'SELF_ID';

          return (
            <ListItem
              key={variable_name}
              value={variable_name}
              sx={{
                borderBottom: `1px solid ${theme.palette.divider}`,
                paddingRight: 1,
                gap: 1,
              }}
            >
              {isAttributeWidget ? (
                <FintelTemplateWidgetAttribute
                  key={variable_name}
                  widgetType={widget.type}
                  onOpenPopover={handleOpenPopover}
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
                  onOpenPopover={handleOpenPopover}
                />
              )}
            </ListItem>
          );
        })}
      </List>
    </>
  );
};

export default FintelTemplateWidgetsList;
