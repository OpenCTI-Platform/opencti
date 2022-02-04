import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { ViewListOutlined, ViewColumnOutlined } from '@material-ui/icons';
import { ProgressWrench } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import StixDomainObjectAttackPatternsKillChainMatrix from './StixDomainObjectAttackPatternsKillChainMatrix';
import StixDomainObjectAttackPatternsKillChainLines from './StixDomainObjectAttackPatternsKillChainLines';
import ExportButtons from '../../../../components/ExportButtons';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
  export: {
    float: 'right',
  },
});

class StixDomainObjectAttackPatternsKillChainComponent extends Component {
  render() {
    const {
      t,
      classes,
      data,
      stixDomainObjectId,
      entityLink,
      handleSearch,
      handleChangeView,
      searchTerm,
      currentView,
    } = this.props;
    const paginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: ['Attack-Pattern'],
      relationship_type: 'uses',
      search: searchTerm,
    };
    let csvData = null;
    if (currentView === 'courses-of-action') {
      csvData = R.pipe(
        R.map((n) => n.node.to.coursesOfAction.edges),
        R.flatten,
        R.map((n) => n.node),
      )(data.stixCoreRelationships.edges);
    }
    return (
      <div className={classes.container}>
        <SearchInput
          variant="small"
          keyword={searchTerm}
          onSubmit={handleSearch.bind(this)}
        />
        <div style={{ float: 'right', marginTop: -5 }}>
          <Tooltip title={t('Matrix view')}>
            <IconButton
              color={currentView === 'matrix' ? 'secondary' : 'primary'}
              onClick={handleChangeView.bind(this, 'matrix')}
            >
              <ViewColumnOutlined />
            </IconButton>
          </Tooltip>
          <Tooltip title={t('Kill chain view')}>
            <IconButton
              color={currentView === 'list' ? 'secondary' : 'primary'}
              onClick={handleChangeView.bind(this, 'list')}
            >
              <ViewListOutlined />
            </IconButton>
          </Tooltip>
          <Tooltip title={t('Courses of action view')}>
            <IconButton
              color={
                currentView === 'courses-of-action' ? 'secondary' : 'primary'
              }
              onClick={handleChangeView.bind(this, 'courses-of-action')}
            >
              <ProgressWrench />
            </IconButton>
          </Tooltip>
          <div className={classes.export}>
            <ExportButtons
              domElementId="container"
              name={t('Attack patterns kill chain')}
              csvData={csvData}
            />
          </div>
        </div>
        {currentView === 'list' && (
          <StixDomainObjectAttackPatternsKillChainLines
            data={data}
            entityLink={entityLink}
            paginationOptions={paginationOptions}
            handleDelete={this.props.relay.refetch.bind(this)}
            searchTerm={searchTerm}
          />
        )}
        {currentView === 'matrix' && (
          <StixDomainObjectAttackPatternsKillChainMatrix
            data={data}
            entityLink={entityLink}
            searchTerm={searchTerm}
          />
        )}
        {currentView === 'courses-of-action' && (
          <StixDomainObjectAttackPatternsKillChainLines
            data={data}
            entityLink={entityLink}
            paginationOptions={paginationOptions}
            handleDelete={this.props.relay.refetch.bind(this)}
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
          />
        </Security>
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
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery(
    $elementId: String
    $elementWithTargetTypes: [String]
    $first: Int
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
          first: $first
        ) {
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
