import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent } from 'react';
import { renderIcon, widgetVisualizationTypes } from './widgetUtils';
import { useFormatter } from '../../../components/i18n';

interface WidgetCreationTypesProps {
  handleSelectType: (type: string) => void,
}
const WidgetCreationTypes: FunctionComponent<WidgetCreationTypesProps> = ({
  handleSelectType,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Grid
      container={true}
      spacing={3}
      style={{ marginTop: 20, marginBottom: 20 }}
    >
      {widgetVisualizationTypes.map((visualizationType) => (
        <Grid key={visualizationType.key} item xs={4}>
          <Card
            variant="outlined"
            style={{
              height: 100,
              textAlign: 'center',
            }}
          >
            <CardActionArea
              onClick={() => handleSelectType(visualizationType.key)}
              style={{ height: '100%' }}
              aria-label={t_i18n(visualizationType.name)}
            >
              <CardContent>
                {renderIcon(visualizationType.key)}
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
