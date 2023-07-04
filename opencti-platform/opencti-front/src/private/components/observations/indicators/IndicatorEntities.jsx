import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import IndicatorEntitiesLines, {
  indicatorEntitiesLinesQuery,
} from './IndicatorEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

const styles = () => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
});

class IndicatorEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  renderLines(platformModuleHelpers, paginationOptions) {
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
    const { indicatorId } = this.props;
    const { sortBy, orderAsc } = this.state;
    const link = `/dashboard/observations/indicators/${indicatorId}/knowledge`;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '10%',
        isSortable: true,
      },
      entity_type: {
        label: 'Entity type',
        width: '12%',
        isSortable: false,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      start_time: {
        label: 'First obs.',
        width: '10%',
        isSortable: true,
      },
      stop_time: {
        label: 'Last obs.',
        width: '10%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
        secondaryAction={true}
        noBottomPadding={true}
      >
        <QueryRenderer
          query={indicatorEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IndicatorEntitiesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              entityId={indicatorId}
              displayRelation={true}
              entityLink={link}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { view, sortBy, orderAsc, searchTerm } = this.state;
    const {
      indicatorId,
      relationshipType,
      classes,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const paginationOptions = {
      fromId: indicatorId,
      relationship_type: relationshipType || 'stix-core-relationship',
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <UserContext.Consumer>
          {({ platformModuleHelpers }) => (
            <>
              {view === 'lines'
                ? this.renderLines(platformModuleHelpers, paginationOptions)
                : ''}
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <StixCoreRelationshipCreationFromEntity
                  paginationOptions={paginationOptions}
                  entityId={indicatorId}
                  isRelationReversed={false}
                  targetStixDomainObjectTypes={[
                    'Theat-Actor-Group',
                    'Intrusion-Set',
                    'Campaign',
                    'Incident',
                    'Malware',
                    'Infrastructure',
                    'Tool',
                    'Vulnerability',
                    'Attack-Pattern',
                    'Indicator',
                  ]}
                  defaultStartTime={defaultStartTime}
                  defaultStopTime={defaultStopTime}
                />
              </Security>
            </>
          )}
        </UserContext.Consumer>
      </div>
    );
  }
}

IndicatorEntities.propTypes = {
  indicatorId: PropTypes.string,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(IndicatorEntities);
