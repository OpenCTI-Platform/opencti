import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectHistoryLines, {
  stixCoreObjectHistoryLinesQuery,
} from './StixCoreObjectHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';

class StixCoreObjectLatestHistory extends Component {
  render() {
    const { t, stixCoreObjectId } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QueryRenderer
          query={stixCoreObjectHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'entity_id', values: [stixCoreObjectId] },
              {
                key: 'event_type',
                values: ['create', 'update', 'merge'],
              },
            ],
            first: 6,
            orderBy: 'timestamp',
            orderMode: 'desc',
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreObjectHistoryLines
                  stixCoreObjectId={stixCoreObjectId}
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

StixCoreObjectLatestHistory.propTypes = {
  t: PropTypes.func,
  stixCoreObjectId: PropTypes.string,
};

export default inject18n(StixCoreObjectLatestHistory);
