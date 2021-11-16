/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { QueryRenderer as QR } from 'react-relay';
import Typography from '@material-ui/core/Typography';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
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
        <QR
          environment={QueryRendererDarkLight}
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
