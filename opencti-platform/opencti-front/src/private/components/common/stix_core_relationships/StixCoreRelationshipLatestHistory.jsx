import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';
import { Typography } from '@components';

class StixCoreRelationshipLatestHistory extends Component {
  render() {
    const { t, stixCoreRelationshipId } = this.props;
    return (
      <div className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QueryRenderer
          query={stixCoreObjectHistoryLinesQuery}
          variables={{
            filters: {
              mode: 'and',
              filterGroups: [],
              filters: [
                { key: 'context_data.id', values: [stixCoreRelationshipId] },
                { key: 'event_type', values: ['mutation', 'create', 'update', 'delete', 'merge'] },
              ],
            },
            first: 7,
            orderBy: 'timestamp',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreRelationshipHistoryLines
                  stixCoreRelationshipId={stixCoreRelationshipId}
                  data={props}
                  isRelationLog={false}
                />
              );
            }
            return <div />;
          }}
        />
      </div>
    );
  }
}

StixCoreRelationshipLatestHistory.propTypes = {
  t: PropTypes.func,
  stixCoreRelationshipId: PropTypes.string,
};

export default inject18n(StixCoreRelationshipLatestHistory);
