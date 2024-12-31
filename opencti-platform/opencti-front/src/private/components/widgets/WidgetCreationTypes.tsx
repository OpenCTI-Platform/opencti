import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent } from 'react';
import { FormatShapesOutlined, MapOutlined, PieChartOutlined, ViewQuiltOutlined } from '@mui/icons-material';
import {
  AlignHorizontalLeft,
  ChartAreasplineVariant,
  ChartBar,
  ChartBubble,
  ChartDonut,
  ChartLine,
  ChartTimeline,
  ChartTree,
  Counter,
  FormatListNumberedRtl,
  Radar,
  StarSettingsOutline,
  ViewListOutline,
} from 'mdi-material-ui';
import { widgetVisualizationTypes } from './widgetUtils';
import { useFormatter } from '../../../components/i18n';

interface WidgetCreationTypesProps {
  handleSelectType: (type: string) => void,
}
const WidgetCreationTypes: FunctionComponent<WidgetCreationTypesProps> = ({
  handleSelectType,
}) => {
  const { t_i18n } = useFormatter();

  const renderIcon = (key: string) => {
    switch (key) {
      case 'map':
        return <MapOutlined fontSize="large" color="primary"/>;
      case 'horizontal-bar':
        return <AlignHorizontalLeft fontSize="large" color="primary"/>;
      case 'vertical-bar':
        return <ChartBar fontSize="large" color="primary"/>;
      case 'donut':
        return <ChartDonut fontSize="large" color="primary"/>;
      case 'area':
        return <ChartAreasplineVariant fontSize="large" color="primary"/>;
      case 'timeline':
        return <ChartTimeline fontSize="large" color="primary"/>;
      case 'list':
        return <ViewListOutline fontSize="large" color="primary"/>;
      case 'distribution-list':
        return <FormatListNumberedRtl fontSize="large" color="primary"/>;
      case 'number':
        return <Counter fontSize="large" color="primary"/>;
      case 'text':
        return <FormatShapesOutlined fontSize="large" color="primary"/>;
      case 'heatmap':
        return <ChartBubble fontSize="large" color="primary"/>;
      case 'line':
        return <ChartLine fontSize="large" color="primary"/>;
      case 'radar':
        return <Radar fontSize="large" color="primary"/>;
      case 'polar-area':
        return <PieChartOutlined fontSize="large" color="primary"/>;
      case 'tree':
        return <ChartTree fontSize="large" color="primary"/>;
      case 'bookmark':
        return <StarSettingsOutline fontSize="large" color="primary"/>;
      case 'wordcloud':
        return <ViewQuiltOutlined fontSize="large" color="primary"/>;
      default:
        return <div>${t_i18n('This widget type is not implemented')}</div>;
    }
  };

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
