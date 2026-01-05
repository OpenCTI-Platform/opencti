import Grid from '@mui/material/Grid';
import CardContent from '@mui/material/CardContent';
import { DatabaseOutline, FlaskOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { LibraryBooksOutlined } from '@mui/icons-material';
import React from 'react';
import { v4 as uuid } from 'uuid';
import { getDefaultWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import { useFormatter } from '../../../components/i18n';
import { indexedVisualizationTypes, WidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { useWidgetConfigContext } from './WidgetConfigContext';
import type { WidgetPerspective } from '../../../utils/widget/widget';
import { emptyFilterGroup, SELF_ID } from '../../../utils/filters/filtersUtils';
import Card from '../../../components/common/card/Card';

const WidgetCreationPerspective = () => {
  const { t_i18n } = useFormatter();
  const { context, config, setStep, setConfigWidget } = useWidgetConfigContext();
  const { type, dataSelection } = config.widget;

  const handleSelectPerspective = (perspective: WidgetPerspective) => {
    const fintelTemplateEntitiesInitialFilters = {
      mode: 'and',
      filters: [{
        id: uuid(),
        key: 'objects',
        values: [SELF_ID],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const initialFilters = context === 'fintelTemplate'
      ? fintelTemplateEntitiesInitialFilters
      : emptyFilterGroup;
    const initialColumns = perspective === 'entities' || perspective === 'relationships'
      ? getDefaultWidgetColumns(perspective, context)
      : [];
    const newDataSelection = dataSelection.map((n) => ({
      ...n,
      perspective,
      filters: perspective === n.perspective ? n.filters : initialFilters,
      dynamicFrom: perspective === n.perspective ? n.dynamicFrom : emptyFilterGroup,
      dynamicTo: perspective === n.perspective ? n.dynamicTo : emptyFilterGroup,
      columns: perspective === n.perspective ? n.columns : initialColumns,
    }
    ));
    setConfigWidget({
      ...config.widget,
      perspective,
      dataSelection: newDataSelection,
    });
    setStep(2);
  };

  const getCurrentIsEntities = () => {
    return indexedVisualizationTypes[type as WidgetVisualizationTypes]?.isEntities ?? false;
  };
  const getCurrentIsAudits = () => {
    return (context !== 'fintelTemplate' && indexedVisualizationTypes[type as WidgetVisualizationTypes]?.isAudits) ?? false;
  };
  const getCurrentIsRelationships = () => {
    return indexedVisualizationTypes[type as WidgetVisualizationTypes]?.isRelationships ?? false;
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
            noPadding
            onClick={() => handleSelectPerspective('entities')}
            variant="outlined"
            sx={{
              textAlign: 'center',
            }}
          >
            <CardContent>
              <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
              <Typography
                gutterBottom
                variant="h2"
                style={{ marginTop: 20 }}
              >
                {t_i18n('Entities')}
              </Typography>
              <br />
              <Typography variant="body1">
                {t_i18n('Display global knowledge with filters and criteria.')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      )}
      {getCurrentIsRelationships() && (
        <Grid item xs={xs}>
          <Card
            noPadding
            onClick={() => handleSelectPerspective('relationships')}
            variant="outlined"
            sx={{
              textAlign: 'center',
            }}
          >
            <CardContent>
              <FlaskOutline style={{ fontSize: 40 }} color="primary" />
              <Typography
                gutterBottom
                variant="h2"
                style={{ marginTop: 20 }}
              >
                {t_i18n('Knowledge graph')}
              </Typography>
              <br />
              <Typography variant="body1">
                {t_i18n(
                  'Display specific knowledge using relationships and filters.',
                )}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      )}
      {getCurrentIsAudits() && (
        <Grid item xs={xs}>
          <Card
            noPadding
            onClick={() => handleSelectPerspective('audits')}
            variant="outlined"
            sx={{
              textAlign: 'center',
            }}
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
              <br />
              <Typography variant="body1">
                {t_i18n('Display data related to the history and activity.')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      )}
    </Grid>
  );
};

export default WidgetCreationPerspective;
