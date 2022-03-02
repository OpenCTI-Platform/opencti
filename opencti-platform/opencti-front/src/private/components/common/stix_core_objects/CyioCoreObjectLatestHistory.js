import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { QueryRenderer as QR } from 'react-relay';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
// import CyioCoreObjectHistoryLines, {
//   cyioCoreObjectHistoryLinesQuery,
// } from './CyioCoreObjectHistoryLines';
// import { QueryRenderer } from '../../../../relay/environment';

class CyioCoreObjectLatestHistory extends Component {
  render() {
    const { t, cyioCoreObjectId } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Most recent history')}
        </Typography>
        <QR
          environment={QueryRendererDarkLight}
          // query={cyioCoreObjectHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'entity_id', values: [cyioCoreObjectId] },
              {
                key: 'event_type',
                values: ['create', 'update', 'merge'],
              },
            ],
            first: 6,
            orderBy: 'timestamp',
            orderMode: 'desc',
          }}
          render={() => <Paper style={{ height: '100%', margin: '10px 0 0 0' }} elevation={2} /> }
        />
      </div>
    );
  }
}

CyioCoreObjectLatestHistory.propTypes = {
  t: PropTypes.func,
  cyioCoreObjectId: PropTypes.string,
};

export default inject18n(CyioCoreObjectLatestHistory);
