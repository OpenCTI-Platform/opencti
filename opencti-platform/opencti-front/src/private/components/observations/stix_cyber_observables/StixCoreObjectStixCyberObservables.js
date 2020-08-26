import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import StixCoreObjectStixCyberObservablesLines, {
  stixCoreObjectStixCyberObservablesLinesQuery,
} from './StixCoreObjectStixCyberObservablesLines';
import StixCyberObservablesRightBar from './StixCyberObservablesRightBar';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

class StixCoreObjectStixCyberObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      targetStixDomainObjectTypes: ['Stix-Cyber-Observable'],
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggle(type) {
    if (this.state.targetStixDomainObjectTypes.includes(type)) {
      this.setState({
        targetStixDomainObjectTypes:
          filter((t) => t !== type, this.state.targetStixDomainObjectTypes)
            .length === 0
            ? ['Stix-Cyber-Observable']
            : filter((t) => t !== type, this.state.targetStixDomainObjectTypes),
      });
    } else {
      this.setState({
        targetStixDomainObjectTypes: append(
          type,
          filter(
            (t) => t !== 'Stix-Cyber-Observable',
            this.state.targetStixDomainObjectTypes,
          ),
        ),
      });
    }
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { stixCoreObjectLink } = this.props;
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
      start_time: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      confidence: {
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
          query={stixCoreObjectStixCyberObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixCoreObjectStixCyberObservablesLines
              data={props}
              paginationOptions={paginationOptions}
              stixCoreObjectLink={stixCoreObjectLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { stixCoreObjectId, relationshipType } = this.props;
    const {
      view, targetStixDomainObjectTypes, sortBy, orderAsc,
    } = this.state;
    const paginationOptions = {
      inferred: false,
      toTypes: targetStixDomainObjectTypes,
      fromId: stixCoreObjectId,
      relationship_type: relationshipType,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixCoreRelationshipCreationFromEntity
          stixCoreObjectId={stixCoreObjectId}
          targetStixDomainObjectTypes={['Stix-Cyber-Observable']}
          allowedRelationshipTypes={[relationshipType]}
          isRelationReversed={true}
          paddingRight={true}
          paginationOptions={paginationOptions}
        />
        <StixCyberObservablesRightBar
          types={targetStixDomainObjectTypes}
          handleToggle={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

StixCoreObjectStixCyberObservables.propTypes = {
  stixCoreObjectId: PropTypes.string,
  relationshipType: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(StixCoreObjectStixCyberObservables);
