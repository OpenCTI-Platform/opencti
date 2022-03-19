import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, {
  stixCoreObjectHistoryLinesQuery,
} from './StixCoreRelationshipHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';

class StixCoreRelationshipLatestHistory extends Component {
  render() {
    const { t, stixCoreRelationshipId } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QueryRenderer
          query={stixCoreObjectHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'entity_id', values: [stixCoreRelationshipId] },
              {
                key: 'event_type',
                values: ['create', 'update', 'merge'],
              },
            ],
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
