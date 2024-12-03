import React, { FunctionComponent } from 'react';
import { List, Alert, Button, Typography } from '@mui/material';
import { Link, useParams } from 'react-router-dom';
import FintelTemplateWidgetDefault from './FintelTemplateWidgetDefault';
import FintelTemplateWidgetAttribute from './FintelTemplateWidgetAttribute';
import { useFormatter } from '../../../../../components/i18n';
import type { Widget } from '../../../../../utils/widget/widget';
import { SELF_ID } from '../../../../../utils/filters/filtersUtils';

export interface FintelTemplateWidget {
  variable_name: string
  widget: Widget
}

interface FintelTemplateWidgetsListProps {
  widgets: FintelTemplateWidget[]
  onCreateWidget: () => void
  onDeleteWidget: (w: FintelTemplateWidget) => void
  onUpdateWidget: (w: FintelTemplateWidget) => void
}

const FintelTemplateWidgetsList: FunctionComponent<FintelTemplateWidgetsListProps> = ({
  widgets,
  onCreateWidget,
  onDeleteWidget,
  onUpdateWidget,
}) => {
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  return (
    <>
      <Button
        variant="outlined"
        sx={{ marginLeft: 2, marginRight: 2 }}
        onClick={onCreateWidget}
      >
        {t_i18n('Add data in content')}
      </Button>

      <Alert severity="info" variant="outlined" sx={{ margin: 2, marginTop: 1, marginBottom: 0 }}>
        <Typography variant="body2" gutterBottom>
          {t_i18n('First, create widgets detailing which data to get. Then, copy paste the widget name in your content.')}
        </Typography>
        <Typography variant="body2">
          {t_i18n('', {
            id: 'Find examples on our documentation.',
            // TODO put link to the doc when written
            values: { link: <Link target="_blank" to="https://docs.opencti.io/latest/">{t_i18n('documentation')}</Link> },
          })}
        </Typography>
      </Alert>

      <List>
        {widgets.map((fintelWidget) => {
          const { variable_name, widget } = fintelWidget;
          const isAttributeWidget = widget.type === 'attribute';
          const isSelfAttributeWidget = isAttributeWidget && widget.dataSelection[0].instance_id === SELF_ID;

          return isAttributeWidget ? (
            <FintelTemplateWidgetAttribute
              key={variable_name}
              widget={widget}
              onUpdate={() => onUpdateWidget(fintelWidget)}
              onDelete={!isSelfAttributeWidget
                ? () => onDeleteWidget(fintelWidget)
                : undefined
              }
              variableName={isSelfAttributeWidget
                ? t_i18n('', {
                  id: 'Attributes of the instance',
                  values: { type: subTypeId ?? '' },
                })
                : variable_name
              }
            />
          ) : (
            <FintelTemplateWidgetDefault
              key={variable_name}
              widget={widget}
              variableName={variable_name}
              onUpdate={() => onUpdateWidget(fintelWidget)}
              onDelete={() => onDeleteWidget(fintelWidget)}
            />
          );
        })}
      </List>
    </>
  );
};

export default FintelTemplateWidgetsList;
