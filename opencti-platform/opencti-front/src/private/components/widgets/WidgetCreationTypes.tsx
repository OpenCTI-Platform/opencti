import Grid from '@mui/material/Grid';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import React from 'react';
import { useWidgetConfigContext } from './WidgetConfigContext';
import { useFormatter } from '../../../components/i18n';
import {
  fintelTemplatesWidgetVisualizationTypes,
  renderWidgetIcon,
  workspacesWidgetVisualizationTypes,
  WidgetVisualizationTypes,
  customViewsWidgetVisualizationTypes,
} from '../../../utils/widget/widgetUtils';
import Card from '../../../components/common/card/Card';
import type { WidgetHost } from '../../../utils/widget/widget';
import { TIMELINE_CONTAINER_TYPES } from '../common/timeline/timelineUtils';

export const getVisualizationTypes = (host: WidgetHost) => {
  return host.kind === 'workspace'
    ? workspacesWidgetVisualizationTypes
    : host.kind === 'fintelTemplate'
      ? fintelTemplatesWidgetVisualizationTypes
      : host.kind === 'custom-view'
        // The timeline widget of a custom view shows the timeline of the entity: incidents and cases only
        ? customViewsWidgetVisualizationTypes.filter((type) => type.key !== 'case-timeline' || TIMELINE_CONTAINER_TYPES.includes(host.customViewTargetEntityType))
        : [];
};

const WidgetCreationTypes = () => {
  const { t_i18n } = useFormatter();
  const { host, setStep, setConfigWidget, config } = useWidgetConfigContext();

  const visualizationTypes = getVisualizationTypes(host);

  const changeType = (type: string) => {
    setConfigWidget({ ...config.widget, type: type as WidgetVisualizationTypes });
    setStep(type === 'text' || type === 'attribute' || type === 'custom-attributes' || type === 'case-timeline' ? 3 : 1);
  };

  return (
    <Grid
      container={true}
      spacing={3}
      style={{ marginTop: 20, marginBottom: 20 }}
    >
      {visualizationTypes.map((visualizationType) => (
        <Grid key={visualizationType.key} item xs={4}>
          <Card
            padding="none"
            aria-label={t_i18n(visualizationType.name)}
            onClick={() => changeType(visualizationType.key)}
            variant="outlined"
            sx={{
              textAlign: 'center',
            }}
          >
            <CardContent>
              {renderWidgetIcon(visualizationType.key, 'large')}
              <Typography
                gutterBottom
                variant="body1"
                style={{ marginTop: 8 }}
              >
                {t_i18n(visualizationType.name)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
};

export default WidgetCreationTypes;
