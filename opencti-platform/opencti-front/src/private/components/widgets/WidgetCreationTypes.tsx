import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import React from 'react';
import { useWidgetConfigContext } from './WidgetConfigContext';
import { useFormatter } from '../../../components/i18n';
import { fintelTemplatesWidgetVisualizationTypes, renderWidgetIcon, workspacesWidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';

const WidgetCreationTypes = () => {
  const { t_i18n } = useFormatter();
  const { context, setStep, setConfigWidget, config } = useWidgetConfigContext();

  const visualizationTypes = context === 'workspace'
    ? workspacesWidgetVisualizationTypes
    : fintelTemplatesWidgetVisualizationTypes;

  const changeType = (type: string) => {
    setConfigWidget({ ...config.widget, type });
    setStep(type === 'text' || type === 'attribute' ? 3 : 1);
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
            variant="outlined"
            style={{
              height: 100,
              textAlign: 'center',
            }}
          >
            <CardActionArea
              onClick={() => changeType(visualizationType.key)}
              style={{ height: '100%' }}
              aria-label={t_i18n(visualizationType.name)}
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
            </CardActionArea>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
};

export default WidgetCreationTypes;
