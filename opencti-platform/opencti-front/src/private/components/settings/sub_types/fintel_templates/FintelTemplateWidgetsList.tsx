import React, { FunctionComponent } from 'react';
import { List, Alert, Typography } from '@mui/material';
import Button from '@common/button/Button';
import { Link, useParams } from 'react-router-dom';
import FintelTemplateWidgetDefault from './FintelTemplateWidgetDefault';
import FintelTemplateWidgetAttribute from './FintelTemplateWidgetAttribute';
import { useFormatter } from '../../../../../components/i18n';
import type { Widget } from '../../../../../utils/widget/widget';
import { SELF_ID } from '../../../../../utils/filters/filtersUtils';

export interface FintelTemplateWidget {
  variable_name: string;
  widget: Widget;
}

interface FintelTemplateWidgetsListProps {
  widgets: FintelTemplateWidget[];
  onCreateWidget: () => void;
  onDeleteWidget: (w: FintelTemplateWidget) => void;
  onUpdateWidget: (w: FintelTemplateWidget) => void;
}

const FintelTemplateWidgetsList: FunctionComponent<FintelTemplateWidgetsListProps> = ({
  widgets,
  onCreateWidget,
  onDeleteWidget,
  onUpdateWidget,
}) => {
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  const widgetSelfInstance = widgets.find(({ widget }) => widget.dataSelection[0].instance_id === SELF_ID);
  const widgetsNoSelf = widgets.filter(({ widget }) => widget.dataSelection[0].instance_id !== SELF_ID);

  return (
    <>
      <Alert severity="info" variant="outlined" sx={{ margin: 2, marginTop: 0 }}>
        <Typography variant="body2" gutterBottom>
          {t_i18n('First, create widgets detailing which data to get. Then, copy paste the widget name in your template.')}
        </Typography>
        <Typography variant="body2">
          {t_i18n('', {
            id: 'Find examples on our documentation.',
            values: {
              link: (
                <Link target="_blank" to="https://docs.opencti.io/latest/administration/entities/#fintel-templates">
                  {t_i18n('documentation')}
                </Link>
              ),
            },
          })}
        </Typography>
      </Alert>

      {widgetSelfInstance && (
        <>
          <Button
            variant="secondary"
            sx={{ marginLeft: 2, marginRight: 2 }}
            onClick={() => onUpdateWidget(widgetSelfInstance)}
          >
            {t_i18n('', {
              id: 'Add attributes of the instance',
              values: { type: subTypeId ?? '' },
            })}
          </Button>

          <FintelTemplateWidgetAttribute
            variableName={widgetSelfInstance.variable_name}
            widget={widgetSelfInstance.widget}
            title={t_i18n('', {
              id: 'Attributes of the instance',
              values: { type: subTypeId ?? '' },
            })}
          />
        </>
      )}

      <Button
        variant="secondary"
        sx={{ marginLeft: 2, marginRight: 2, marginTop: 2 }}
        onClick={onCreateWidget}
      >
        {t_i18n('Add related data')}
      </Button>

      <List>
        {widgetsNoSelf.length === 0 && (
          <Typography sx={{ marginLeft: 2, marginTop: 1 }} variant="body2">
            {t_i18n('No related data added yet')}
          </Typography>
        )}

        {widgetsNoSelf.map((fintelWidget) => {
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
