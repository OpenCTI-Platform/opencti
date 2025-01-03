import Grid from '@mui/material/Grid';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import { DatabaseOutline, FlaskOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { LibraryBooksOutlined } from '@mui/icons-material';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../components/i18n';
import { indexedVisualizationTypes, WidgetPerspective } from './widgetUtils';

interface WidgetCreationPerspectiveProps {
  handleSelectPerspective: (perspective: WidgetPerspective) => void,
  type: string,
}

const WidgetCreationPerspective: FunctionComponent<WidgetCreationPerspectiveProps> = ({
  handleSelectPerspective,
  type,
}) => {
  const { t_i18n } = useFormatter();
  const getCurrentIsEntities = () => {
    return indexedVisualizationTypes[type]?.isEntities ?? false;
  };
  const getCurrentIsAudits = () => {
    return indexedVisualizationTypes[type]?.isAudits ?? false;
  };
  const getCurrentIsRelationships = () => {
    return indexedVisualizationTypes[type]?.isRelationships ?? false;
  };

  let xs = 12;
  if (
    getCurrentIsEntities()
    && getCurrentIsRelationships()
    && getCurrentIsAudits()
  ) {
    xs = 4;
  } else if (getCurrentIsEntities() && getCurrentIsRelationships()) {
    xs = 6;
  }

  return (
    <Grid
      container={true}
      spacing={3}
      style={{ marginTop: 20, marginBottom: 20 }}
    >
      {getCurrentIsEntities() && (
        <Grid item xs={xs}>
          <Card
            variant="outlined"
            style={{
              height: 180,
              textAlign: 'center',
            }}
          >
            <CardActionArea
              onClick={() => handleSelectPerspective(WidgetPerspective.entities)}
              style={{ height: '100%' }}
              aria-label={t_i18n('Entities')}
            >
              <CardContent>
                <DatabaseOutline style={{ fontSize: 40 }} color="primary"/>
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Entities')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n('Display global knowledge with filters and criteria.')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      )}
      {getCurrentIsRelationships() && (
        <Grid item xs={xs}>
          <Card
            variant="outlined"
            style={{
              height: 180,
              textAlign: 'center',
            }}
          >
            <CardActionArea
              onClick={() => handleSelectPerspective(WidgetPerspective.relationships)}
              style={{ height: '100%' }}
              aria-label={t_i18n('Knowledge graph')}
            >
              <CardContent>
                <FlaskOutline style={{ fontSize: 40 }} color="primary"/>
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Knowledge graph')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n(
                    'Display specific knowledge using relationships and filters.',
                  )}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      )}
      {getCurrentIsAudits() && (
        <Grid item xs={xs}>
          <Card
            variant="outlined"
            style={{
              height: 180,
              textAlign: 'center',
            }}
          >
            <CardActionArea
              onClick={() => handleSelectPerspective(WidgetPerspective.audits)}
              style={{ height: '100%' }}
              aria-label={t_i18n('Activity & history')}
            >
              <CardContent>
                <LibraryBooksOutlined
                  style={{ fontSize: 40 }}
                  color="primary"
                />
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Activity & history')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n('Display data related to the history and activity.')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
      )}
    </Grid>
  );
};

export default WidgetCreationPerspective;
