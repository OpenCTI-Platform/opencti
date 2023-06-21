import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Chip from '@mui/material/Chip';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';
import { convertFilters } from '../../../../utils/ListParameters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { truncate } from '../../../../utils/String';
import Filters from '../lists/Filters';
import ItemMarkings from '../../../../components/ItemMarkings';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
    marginBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
  parameters: {
    margin: '0 0 20px 0',
    padding: 0,
  },
  filters: {
    float: 'left',
    margin: '-4px 0 0 15px',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 0 10px',
  },
  export: {
    float: 'right',
    margin: '0 0 0 20px',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

const inlineStyles = {
  itemAuthor: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    marginLeft: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemDate: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const stixDomainObjectsListQuery = graphql`
  query StixDomainObjectsListQuery(
    $types: [String]
    $first: Int
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainObjectsFiltering]
  ) {
    stixDomainObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          created
          created_at
          modified
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on ThreatActorGroup {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                definition
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

class StixDomainObjectsList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      filters: R.propOr({}, 'filters', props.config),
    };
  }

  handleSaveConfig() {
    const { config, onConfigChange } = this.props;
    const { filters } = this.state;
    onConfigChange({ ...config, filters });
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.handleSaveConfig(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.handleSaveConfig(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.handleSaveConfig());
  }

  renderContent() {
    const { filters } = this.state;
    const {
      t,
      fsd,
      containerId,
      dateAttribute,
      classes,
      types,
      startDate,
      endDate,
    } = this.props;
    const finalFilters = convertFilters(filters);
    if (containerId) {
      finalFilters.push({
        key: 'objectContains',
        values: [containerId],
      });
    }
    if (startDate) {
      finalFilters.push({
        key: 'created',
        values: [startDate],
        operator: 'gt',
      });
    }
    if (endDate) {
      finalFilters.push({
        key: 'created',
        values: [endDate],
        operator: 'lt',
      });
    }
    return (
      <QueryRenderer
        query={stixDomainObjectsListQuery}
        variables={{
          types: types || ['Stix-Domain-Object'],
          first: 50,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters: finalFilters,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixDomainObjects
            && props.stixDomainObjects.edges.length > 0
          ) {
            const data = props.stixDomainObjects.edges;
            return (
              <div id="container" className={classes.container}>
                <List style={{ marginTop: -10 }}>
                  {data.map((stixCoreObjectEdge) => {
                    const stixCoreObject = stixCoreObjectEdge.node;
                    return (
                      <ListItem
                        key={stixCoreObject.id}
                        dense={true}
                        button={true}
                        classes={{ root: classes.item }}
                        divider={true}
                        component={Link}
                        to={`${resolveLink(stixCoreObject.entity_type)}/${
                          stixCoreObject.id
                        }`}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            type={stixCoreObject.entity_type}
                            color="primary"
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <div className={classes.itemText}>
                              {defaultValue(stixCoreObject)}
                            </div>
                          }
                        />
                        <div style={inlineStyles.itemAuthor}>
                          {R.pathOr('', ['createdBy', 'name'], stixCoreObject)}
                        </div>
                        <div style={inlineStyles.itemDate}>
                          {fsd(stixCoreObject[dateAttribute])}
                        </div>
                        <div style={{ width: 110, paddingRight: 20 }}>
                          <ItemMarkings
                            variant="inList"
                            markingDefinitionsEdges={
                              stixCoreObject.objectMarking.edges
                            }
                            limit={1}
                          />
                        </div>
                      </ListItem>
                    );
                  })}
                </List>
              </div>
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const { filters } = this.state;
    const { t, classes, title, variant, height, onConfigChange } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <div
          className={classes.parameters}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{
              float: 'left',
              margin: '2px 20px 0 0',
            }}
          >
            {title || t('Reports list')}
          </Typography>
          {onConfigChange && (
            <Security needs={[EXPLORE_EXUPDATE]}>
              <div style={{ marginTop: -4, float: 'left' }}>
                <Filters
                  availableFilterKeys={[
                    'markedBy',
                    'createdBy',
                    'labelledBy',
                    'confidence',
                  ]}
                  handleAddFilter={this.handleAddFilter.bind(this)}
                  handleRemoveFilter={this.handleRemoveFilter.bind(this)}
                  size="small"
                />
              </div>
            </Security>
          )}
          <div className={classes.filters}>
            {R.map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const localFilterMode = currentFilter[0].endsWith('not_eq')
                ? t('AND')
                : t('OR');
              const values = (
                <span>
                  {R.map(
                    (n) => (
                      <span key={n.value}>
                        {n.value && n.value.length > 0
                          ? truncate(n.value, 15)
                          : t('No label')}{' '}
                        {R.last(currentFilter[1]).value !== n.value && (
                          <code>{localFilterMode}</code>
                        )}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <Tooltip
                  key={label}
                  title={
                    <div>
                      <strong>{label}</strong>: {values}
                    </div>
                  }
                >
                  <span>
                    <Security
                      needs={[EXPLORE_EXUPDATE]}
                      placeholder={
                        <Chip
                          key={currentFilter[0]}
                          label={
                            <div>
                              <strong>{label}</strong>: {values}
                            </div>
                          }
                          size="small"
                        />
                      }
                    >
                      <Chip
                        key={currentFilter[0]}
                        label={
                          <div>
                            <strong>{label}</strong>: {values}
                          </div>
                        }
                        onDelete={this.handleRemoveFilter.bind(
                          this,
                          currentFilter[0],
                        )}
                        size="small"
                      />
                    </Security>
                    {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                      <Chip
                        size="small"
                        classes={{ root: classes.operator }}
                        label={t('AND')}
                      />
                    )}
                  </span>
                </Tooltip>
              );
            }, R.toPairs(filters))}
          </div>
          <div className="clearfix" />
        </div>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

StixDomainObjectsList.propTypes = {
  title: PropTypes.string,
  containerId: PropTypes.string,
  types: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
  config: PropTypes.object,
  onConfigChange: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectsList);
