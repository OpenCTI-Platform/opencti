import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import UserHistoryLines, { userHistoryLinesQuery } from './UserHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';
import SearchInput from '../../../../components/SearchInput';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class UserHistory extends Component {
  constructor(props) {
    super(props);
    this.state = { entitySearchTerm: '' };
  }

  handleSearchEntity(value) {
    this.setState({ entitySearchTerm: value });
  }

  render() {
    const { t, userId } = this.props;
    const { entitySearchTerm } = this.state;
    return (
      <div style={{ marginTop: 50 }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ float: 'left', marginTop: 12 }}
        >
          {t('History')}
        </Typography>
        <div style={{ float: 'right' }}>
          <SearchInput
            variant="small"
            onSubmit={this.handleSearchEntity.bind(this)}
            keyword={entitySearchTerm}
          />
        </div>
        <div className="clearfix" />
        <QueryRenderer
          query={userHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'user_id', values: [userId], operator: 'wildcard' },
            ],
            first: 20,
            orderBy: 'timestamp',
            orderMode: 'desc',
            search: entitySearchTerm,
          }}
          render={({ props }) => {
            if (props) {
              return (
                <UserHistoryLines
                  userId={userId}
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

UserHistory.propTypes = {
  t: PropTypes.func,
  userId: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(UserHistory);
