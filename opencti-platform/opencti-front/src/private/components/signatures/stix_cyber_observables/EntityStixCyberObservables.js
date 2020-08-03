import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import EntityStixCyberObservablesLines, {
  entityStixCyberObservablesLinesQuery,
} from './EntityStixCyberObservablesLines';
import StixCyberObservablesRightBar from './StixCyberObservablesRightBar';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

class EntityStixCyberObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      targetEntityTypes: ['Stix-Cyber-Observable'],
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggle(type) {
    if (this.state.targetEntityTypes.includes(type)) {
      this.setState({
        targetEntityTypes:
          filter((t) => t !== type, this.state.targetEntityTypes).length === 0
            ? ['Stix-Cyber-Observable']
            : filter((t) => t !== type, this.state.targetEntityTypes),
      });
    } else {
      this.setState({
        targetEntityTypes: append(
          type,
          filter((t) => t !== 'Stix-Cyber-Observable', this.state.targetEntityTypes),
        ),
      });
    }
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: false,
      },
      observable_value: {
        label: 'Value',
        width: '30%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      weight: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        displayImport={false}
        secondaryAction={true}
      >
        <QueryRenderer
          query={entityStixCyberObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixCyberObservablesLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { entityId, relationship_type } = this.props;
    const {
      view, targetEntityTypes, sortBy, orderAsc,
    } = this.state;
    const paginationOptions = {
      inferred: false,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationship_type,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          targetEntityTypes={['Stix-Cyber-Observable']}
          allowedRelationshipTypes={[relationship_type]}
          onlyObservables={true}
          isFrom={false}
          paddingRight={true}
          paginationOptions={paginationOptions}
        />
        <StixCyberObservablesRightBar
          types={targetEntityTypes}
          handleToggle={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

EntityStixCyberObservables.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(EntityStixCyberObservables);
