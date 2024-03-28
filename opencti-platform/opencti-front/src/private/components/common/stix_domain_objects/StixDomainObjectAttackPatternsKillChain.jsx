import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { createRefetchContainer, graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, FilterAltOutlined, InvertColorsOffOutlined, ViewColumnOutlined, ViewListOutlined } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import IconButton from '@mui/material/IconButton';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT } from '../../../../utils/hooks/useGranted';
import StixDomainObjectAttackPatternsKillChainMatrix from './StixDomainObjectAttackPatternsKillChainMatrix';
import StixDomainObjectAttackPatternsKillChainLines from './StixDomainObjectAttackPatternsKillChainLines';
import ExportButtons from '../../../../components/ExportButtons';
import StixCoreRelationshipsExports from '../stix_core_relationships/StixCoreRelationshipsExports';
import Filters from '../lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import { export_max_size } from '../../../../utils/utils';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  parameters: {
    marginBottom: 20,
    padding: 0,
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
      // stixDomainObjectId,
      entityLink,
      handleSearch,
      handleAddFilter,
      handleRemoveFilter,
      handleSwitchLocalMode,
      handleSwitchGlobalMode,
      filters,
      handleChangeView,
      searchTerm,
      currentView,
      paginationOptions,
      openExports,
      handleToggleExports,
      exportContext,
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
    const exportDisabled = targetEntities.length > export_max_size;
    return (
      <>
        <div
          className={classes.parameters}
          style={{ marginTop: -12 }}
        >
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
                  <FilterAltOutlined fontSize="medium"/>
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
                  <InvertColorsOffOutlined fontSize="medium"/>
                </IconButton>
              </span>
            </Tooltip>
          </div>
          <Filters
            availableFilterKeys={[
              'objectMarking',
              'createdBy',
              'created',
            ]}
            handleAddFilter={handleAddFilter}
            handleRemoveFilter={handleRemoveFilter}
            handleSwitchLocalMode={handleSwitchLocalMode}
            handleSwitchGlobalMode={handleSwitchGlobalMode}
          />
          <FilterIconButton
            filters={filters}
            handleRemoveFilter={handleRemoveFilter}
            handleSwitchLocalMode={handleSwitchLocalMode}
            handleSwitchGlobalMode={handleSwitchGlobalMode}
            styleNumber={2}
            redirection
          />
          <div style={{ float: 'right', display: 'flex', margin: 0 }}>
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
              {typeof handleToggleExports === 'function' && !exportDisabled && (
              <Tooltip title={t('Open export panel')}>
                <ToggleButton
                  value="export"
                  aria-label="export"
                  onClick={handleToggleExports.bind(this)}
                >
                  <FileDownloadOutlined
                    fontSize="small"
                    color={openExports ? 'secondary' : 'primary'}
                  />
                </ToggleButton>
              </Tooltip>
              )}
              {typeof handleToggleExports === 'function' && exportDisabled && (
              <Tooltip
                title={`${
                  t(
                    'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                  ) + export_max_size
                })`}
              >
                <span>
                  <ToggleButton
                    size="small"
                    value="export"
                    aria-label="export"
                    disabled={true}
                  >
                    <FileDownloadOutlined fontSize="small"/>
                  </ToggleButton>
                </span>
              </Tooltip>
              )}
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
          <div className="clearfix"/>
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
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixCoreRelationshipsExports
              open={openExports}
              handleToggle={handleToggleExports.bind(this)}
              paginationOptions={paginationOptions}
              exportContext={exportContext}
            />
          </Security>
        </div>
      </>
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
  handleSwitchLocalMode: PropTypes.func,
  handleSwitchGlobalMode: PropTypes.func,
  filters: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery = graphql`
    query StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery(
        $fromOrToId: [String]
        $elementWithTargetTypes: [String]
        $first: Int
        $filters: FilterGroup
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
                    fromOrToId: $fromOrToId
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
                                        id
                                        phase_name
                                        x_opencti_order
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
                                        id
                                        phase_name
                                        x_opencti_order
                                    }
                                }
                            }
                            killChainPhases {
                                id
                                phase_name
                                x_opencti_order
                            }
                            objectMarking {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
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
