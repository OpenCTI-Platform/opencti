import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql, createRefetchContainer } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import {
  ViewListOutlined,
  ViewColumnOutlined,
  InvertColorsOffOutlined,
  FilterAltOutlined,
} from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { last, map, toPairs } from 'ramda';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import StixDomainObjectAttackPatternsKillChainMatrix from './StixDomainObjectAttackPatternsKillChainMatrix';
import StixDomainObjectAttackPatternsKillChainLines from './StixDomainObjectAttackPatternsKillChainLines';
import ExportButtons from '../../../../components/ExportButtons';
import Filters from '../lists/Filters';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  parameters: {
    margin: '0 0 20px 0',
    padding: 0,
  },
  filters: {
    float: 'left',
    margin: '2px 0 0 15px',
  },
  filtersDialog: {
    margin: '0 0 20px 0',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autocomplete: {
    float: 'left',
    margin: '5px 10px 0 10px',
    width: 200,
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.paper,
    margin: '0 10px 10px 0',
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

class StixDomainObjectAttackPatternsKillChainComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentModeOnlyActive: false,
      currentColorsReversed: false,
      targetEntities: [],
    };
  }

  handleToggleModeOnlyActive() {
    this.setState({ currentModeOnlyActive: !this.state.currentModeOnlyActive });
  }

  handleToggleColorsReversed() {
    this.setState({ currentColorsReversed: !this.state.currentColorsReversed });
  }

  handleAdd(entity) {
    this.setState({ targetEntities: [entity] });
  }

  render() {
    const {
      t,
      classes,
      data,
      stixDomainObjectId,
      entityLink,
      handleSearch,
      handleAddFilter,
      handleRemoveFilter,
      filters,
      handleChangeView,
      searchTerm,
      currentView,
      paginationOptions,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const { currentColorsReversed, currentModeOnlyActive, targetEntities } = this.state;
    let csvData = null;
    if (currentView === 'courses-of-action') {
      csvData = R.pipe(
        R.map((n) => n.node.to.coursesOfAction.edges),
        R.flatten,
        R.map((n) => n.node),
      )(data.stixCoreRelationships.edges);
    }
    return (
      <div>
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              keyword={searchTerm}
              onSubmit={handleSearch.bind(this)}
            />
          </div>
          <div
            style={{ float: 'left', display: 'flex', margin: '-6px 4px 0 0' }}
          >
            <Tooltip
              title={
                currentModeOnlyActive
                  ? t('Display the whole matrix')
                  : t('Display only used techniques')
              }
            >
              <span>
                <IconButton
                  color={currentModeOnlyActive ? 'secondary' : 'primary'}
                  onClick={this.handleToggleModeOnlyActive.bind(this)}
                  size="large"
                >
                  <FilterAltOutlined fontSize="medium" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip
              title={
                currentColorsReversed
                  ? t('Disable invert colors')
                  : t('Enable invert colors')
              }
            >
              <span>
                <IconButton
                  color={currentColorsReversed ? 'secondary' : 'primary'}
                  onClick={this.handleToggleColorsReversed.bind(this)}
                  size="large"
                >
                  <InvertColorsOffOutlined fontSize="medium" />
                </IconButton>
              </span>
            </Tooltip>
          </div>
          <Filters
            availableFilterKeys={[
              'markedBy',
              'createdBy',
              'created_start_date',
              'created_end_date',
            ]}
            handleAddFilter={handleAddFilter}
            handleRemoveFilter={handleRemoveFilter}
          />
          <div className={classes.filters}>
            {map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {map(
                    (n) => (
                      <span key={n.value}>
                        {n.value && n.value.length > 0
                          ? truncate(n.value, 15)
                          : t('No label')}{' '}
                        {last(currentFilter[1]).value !== n.value && (
                          <code>OR</code>
                        )}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <span>
                  <Chip
                    key={currentFilter[0]}
                    classes={{ root: classes.fnoTopMarginilter }}
                    label={
                      <div>
                        <strong>{label}</strong>: {values}
                      </div>
                    }
                    onDelete={handleRemoveFilter.bind(this, currentFilter[0])}
                  />
                  {last(toPairs(filters))[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, toPairs(filters))}
          </div>
          <div style={{ float: 'right', margin: 0 }}>
            <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
              <Tooltip title={t('Matrix view')}>
                <ToggleButton onClick={handleChangeView.bind(this, 'matrix')}>
                  <ViewColumnOutlined
                    fontSize="small"
                    color={currentView === 'matrix' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
              <Tooltip title={t('Kill chain view')}>
                <ToggleButton onClick={handleChangeView.bind(this, 'list')}>
                  <ViewListOutlined
                    fontSize="small"
                    color={currentView === 'list' ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
              <Tooltip title={t('Courses of action view')}>
                <ToggleButton
                  onClick={handleChangeView.bind(this, 'courses-of-action')}
                >
                  <ProgressWrench
                    fontSize="small"
                    color={
                      currentView === 'courses-of-action'
                        ? 'secondary'
                        : 'primary'
                    }
                  />
                </ToggleButton>
              </Tooltip>
            </ToggleButtonGroup>
            <div className={classes.export}>
              <ExportButtons
                domElementId="container"
                name={t('Attack patterns kill chain')}
                csvData={csvData}
                csvFileName={`${t('Attack pattern courses of action')}.csv`}
              />
            </div>
          </div>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          {currentView === 'list' && (
            <StixDomainObjectAttackPatternsKillChainLines
              data={data}
              entityLink={entityLink}
              paginationOptions={paginationOptions}
              onDelete={this.props.relay.refetch.bind(this)}
              searchTerm={searchTerm}
            />
          )}
          {currentView === 'matrix' && (
            <StixDomainObjectAttackPatternsKillChainMatrix
              data={data}
              entityLink={entityLink}
              searchTerm={searchTerm}
              handleToggleModeOnlyActive={this.handleToggleModeOnlyActive.bind(
                this,
              )}
              handleToggleColorsReversed={this.handleToggleColorsReversed.bind(
                this,
              )}
              currentColorsReversed={currentColorsReversed}
              currentModeOnlyActive={currentModeOnlyActive}
              handleAdd={this.handleAdd.bind(this)}
            />
          )}
          {currentView === 'courses-of-action' && (
            <StixDomainObjectAttackPatternsKillChainLines
              data={data}
              entityLink={entityLink}
              paginationOptions={paginationOptions}
              onDelete={this.props.relay.refetch.bind(this)}
              searchTerm={searchTerm}
              coursesOfAction={true}
            />
          )}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipCreationFromEntity
              entityId={stixDomainObjectId}
              isRelationReversed={false}
              paddingRight={220}
              onCreate={this.props.relay.refetch.bind(this)}
              targetStixDomainObjectTypes={['Attack-Pattern']}
              paginationOptions={paginationOptions}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              targetEntities={targetEntities}
            />
          </Security>
        </div>
      </div>
    );
  }
}

StixDomainObjectAttackPatternsKillChainComponent.propTypes = {
  data: PropTypes.object,
  entity: PropTypes.object,
  entityLink: PropTypes.string,
  currentView: PropTypes.string,
  searchTerm: PropTypes.string,
  handleChangeView: PropTypes.func,
  handleSearch: PropTypes.func,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  filters: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export const stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery(
    $elementId: [String]
    $elementWithTargetTypes: [String]
    $first: Int
    $filters: [StixCoreRelationshipsFiltering]
  ) {
    ...StixDomainObjectAttackPatternsKillChain_data
  }
`;

const stixDomainObjectAttackPatternsKillChainLines = createRefetchContainer(
  StixDomainObjectAttackPatternsKillChainComponent,
  {
    data: graphql`
      fragment StixDomainObjectAttackPatternsKillChain_data on Query {
        stixCoreRelationships(
          elementId: $elementId
          elementWithTargetTypes: $elementWithTargetTypes
          filters: $filters
          first: $first
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              id
              description
              start_time
              stop_time
              from {
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  id
                  parent_types
                  entity_type
                  name
                  description
                  x_mitre_id
                  x_mitre_platforms
                  x_mitre_permissions_required
                  x_mitre_detection
                  isSubAttackPattern
                  coursesOfAction {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  parentAttackPatterns {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  subAttackPatterns {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
              }
              to {
                ... on BasicRelationship {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  id
                  parent_types
                  entity_type
                  name
                  description
                  x_mitre_id
                  x_mitre_platforms
                  x_mitre_permissions_required
                  x_mitre_detection
                  isSubAttackPattern
                  coursesOfAction {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  parentAttackPatterns {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  subAttackPatterns {
                    edges {
                      node {
                        id
                        name
                        description
                        x_mitre_id
                      }
                    }
                  }
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                    x_opencti_color
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(stixDomainObjectAttackPatternsKillChainLines);
