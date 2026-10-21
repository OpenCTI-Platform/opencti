import Grid from '@mui/material/Grid';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import React from 'react';
import { useWidgetConfigContext } from './WidgetConfigContext';
import { useFormatter } from '../../../components/i18n';
import {
  fintelTemplatesWidgetVisualizationTypes,
  isWidgetWithoutDataSelection,
  renderWidgetIcon,
  workspacesWidgetVisualizationTypes,
  WidgetVisualizationTypes,
  customViewsWidgetVisualizationTypes,
} from '../../../utils/widget/widgetUtils';
import Card from '../../../components/common/card/Card';
import type { WidgetHost } from '../../../utils/widget/widget';
import useGranted, { KNOWLEDGE } from '../../../utils/hooks/useGranted';

export const getVisualizationTypes = (host: WidgetHost, canReadKnowledge = true) => {
  const visualizationTypes = host.kind === 'workspace'
    ? workspacesWidgetVisualizationTypes
    : host.kind === 'fintelTemplate'
      ? fintelTemplatesWidgetVisualizationTypes
      : host.kind === 'custom-view'
        ? customViewsWidgetVisualizationTypes
        : [];
  // The defense widgets read the knowledge of the platform
  return canReadKnowledge ? visualizationTypes : visualizationTypes.filter((visualizationType) => visualizationType.category !== 'defense');
};

const WidgetCreationTypes = () => {
  const { t_i18n } = useFormatter();
  const { host, setStep, setConfigWidget, config } = useWidgetConfigContext();
  const canReadKnowledge = useGranted([KNOWLEDGE]);

  const visualizationTypes = getVisualizationTypes(host, canReadKnowledge);

  const changeType = (type: string) => {
    setConfigWidget({ ...config.widget, type: type as WidgetVisualizationTypes });
    setStep(isWidgetWithoutDataSelection(type) ? 3 : 1);
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
