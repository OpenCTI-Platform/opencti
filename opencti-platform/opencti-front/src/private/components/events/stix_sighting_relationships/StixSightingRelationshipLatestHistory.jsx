import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Typography } from '@components';
import inject18n from '../../../../components/i18n';
import StixSightingRelationshipHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixSightingRelationshipHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';

class StixSightingRelationshipLatestHistory extends Component {
  render() {
    const { t, stixSightingRelationshipId } = this.props;
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QueryRenderer
          query={stixCoreObjectHistoryLinesQuery}
          variables={{
            filters: {
              mode: 'and',
              filters: [
                { key: 'context_data.id', values: [stixSightingRelationshipId] },
                { key: 'event_type', values: ['mutation', 'create', 'update', 'delete', 'merge'] },
              ],
              filterGroups: [],
            },
            first: 6,
            orderBy: 'timestamp',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixSightingRelationshipHistoryLines
                  stixSightingRelationshipId={stixSightingRelationshipId}
                  data={props}
                  isRelationLog={false}
                />
              );
            }
            return <div />;
          }}
        />
      </>
    );
  }
}

StixSightingRelationshipLatestHistory.propTypes = {
  t: PropTypes.func,
  stixSightingRelationshipId: PropTypes.string,
};

export default inject18n(StixSightingRelationshipLatestHistory);
