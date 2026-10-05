import Grid from '@mui/material/Grid';
import CardContent from '@mui/material/CardContent';
import { DatabaseOutline, FlaskOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { LibraryBooksOutlined, RssFeedOutlined } from '@mui/icons-material';
import { v4 as uuid } from 'uuid';
import { getDefaultWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import useAttributes from '../../../utils/hooks/useAttributes';
import useGranted, { INGESTION, MODULES } from '../../../utils/hooks/useGranted';
import { useFormatter } from '../../../components/i18n';
import { getCurrentIsSources, indexedVisualizationTypes, WidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { useWidgetConfigContext } from './WidgetConfigContext';
import type { WidgetHost, WidgetPerspective } from '../../../utils/widget/widget';
import { emptyFilterGroup, SELF_ID } from '../../../utils/filters/filtersUtils';
import Card from '../../../components/common/card/Card';

/**
 * For fintel templates and custom views we want to pre-fill filters
 */
export const buildInitialFilters = (
  containerTypes: string[],
  host: WidgetHost,
  perspective: WidgetPerspective,
) => {
  const hostEntityType = host.kind === 'fintelTemplate'
    ? host.fintelEntityType
    : host.kind === 'custom-view'
      ? host.customViewTargetEntityType
      : null;

  const isContainer = hostEntityType
    ? containerTypes.includes(hostEntityType)
    : false;

  let initialFilters = emptyFilterGroup;
  if (['fintelTemplate', 'custom-view'].includes(host.kind)) {
    let initialFilterKey = 'objects';
    let initialFilterValues: (object | string)[] = [SELF_ID];

    // Handle Non-Container Logic
    if (!isContainer) {
      if (perspective === 'entities') {
        initialFilterKey = 'regardingOf';
        initialFilterValues = [{ key: 'id', values: [SELF_ID] }];
      } else if (perspective === 'relationships') {
        initialFilterKey = host.kind === 'fintelTemplate'
          ? 'fromId'
          : host.kind === 'custom-view'
            ? 'fromOrToId'
            : '';
      } else if (perspective === 'audits') {
        initialFilterKey = host.kind === 'custom-view'
          ? 'contextEntityId'
          : '';
      }
    }
    initialFilters = {
      mode: 'and',
      filters: [{
        id: uuid(),
        key: initialFilterKey,
        values: initialFilterValues,
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
  }
  return initialFilters;
};

const WidgetCreationPerspective = () => {
  const { t_i18n } = useFormatter();
  const { host, config, setStep, setConfigWidget } = useWidgetConfigContext();
  const { type, dataSelection } = config.widget;

  // Container and domain object have different filters for the perspective selection
  const { containerTypes } = useAttributes();
  const isSourcesGranted = useGranted([MODULES, INGESTION]);

  const handleSelectPerspective = (perspective: WidgetPerspective) => {
    const initialFilters = buildInitialFilters(containerTypes, host, perspective);
    const initialColumns = perspective === 'entities' || perspective === 'relationships'
      ? getDefaultWidgetColumns(perspective, host)
      : [];
    const newDataSelection = dataSelection.map((n) => ({
      ...n,
      perspective,
      filters: perspective === n.perspective ? n.filters : initialFilters,
      dynamicFrom: perspective === n.perspective ? n.dynamicFrom : emptyFilterGroup,
      dynamicTo: perspective === n.perspective ? n.dynamicTo : emptyFilterGroup,
      filters_id: undefined,
      dynamicFrom_id: undefined,
      dynamicTo_id: undefined,
      columns: perspective === n.perspective ? n.columns : initialColumns,
      // Source widgets select scorecard metrics: x / y / size for the bubble, a single metric otherwise
      ...(perspective === 'sources' && n.perspective !== 'sources' ? {
        attribute: type === 'bubble' ? 'cost_per_actionable_object' : 'value_score',
        field: type === 'bubble' ? 'impact_score' : undefined,
        sort_by: type === 'bubble' ? 'volume_total' : null,
        sort_mode: type === 'number' || type === 'line' ? 'avg' : 'desc',
      } : {}),
      // Scorecard metrics mean nothing to the other perspectives: back to the defaults of a new widget
      ...(n.perspective === 'sources' && perspective !== 'sources' ? {
        attribute: 'entity_type',
        field: undefined,
        sort_by: 'created_at',
        sort_mode: 'desc',
      } : {}),
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
    return (host.kind !== 'fintelTemplate' && indexedVisualizationTypes[type as WidgetVisualizationTypes]?.isAudits) ?? false;
  };
  const getCurrentIsRelationships = () => {
    return indexedVisualizationTypes[type as WidgetVisualizationTypes]?.isRelationships ?? false;
  };
  // Source scorecards only feed dashboards, never fintel templates or custom views of an entity,
  // and are readable with the connectors or ingestion capability only
  const isSourcesAvailable = isSourcesGranted && host.kind === 'workspace' && getCurrentIsSources(type);

  let xs = 12;
  if (isSourcesAvailable) {
    xs = 12 / [getCurrentIsEntities(), getCurrentIsRelationships(), getCurrentIsAudits(), true].filter(Boolean).length;
  } else if (
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
            data-testid="entities-widget-perspective"
            padding="none"
            aria-label={t_i18n('Entities')}
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
            data-testid="relationships-widget-perspective"
            padding="none"
            aria-label={t_i18n('Knowledge graph')}
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
            data-testid="audits-widget-perspective"
            padding="none"
            aria-label={t_i18n('Activity & history')}
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
      {isSourcesAvailable && (
        <Grid item xs={xs}>
          <Card
            data-testid="sources-widget-perspective"
            padding="none"
            aria-label={t_i18n('Intelligence sources')}
            onClick={() => handleSelectPerspective('sources')}
            variant="outlined"
            sx={{
              textAlign: 'center',
            }}
          >
            <CardContent>
              <RssFeedOutlined
                style={{ fontSize: 40 }}
                color="primary"
              />
              <Typography
                gutterBottom
                variant="h2"
                style={{ marginTop: 20 }}
              >
                {t_i18n('Intelligence sources')}
              </Typography>
              <br />
              <Typography variant="body1">
                {t_i18n('Display the scorecards of connectors, feeds and authors: value, uniqueness, lead time, accuracy, impact, noise and cost.')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      )}
    </Grid>
  );
};

export default WidgetCreationPerspective;
