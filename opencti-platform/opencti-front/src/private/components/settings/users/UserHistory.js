import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import UserHistoryLines, { userHistoryLinesQuery } from './UserHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';
import SearchInput from '../../../../components/SearchInput';

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
      <>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ float: 'left' }}
        >
          {t('History')}
        </Typography>
        <div style={{ float: 'right', marginTop: -12 }}>
          <SearchInput
            variant="thin"
            onSubmit={this.handleSearchEntity.bind(this)}
            keyword={entitySearchTerm}
          />
        </div>
        <div className="clearfix"/>
        <QueryRenderer
          query={userHistoryLinesQuery}
          variables={{
            filters: [
              { key: 'user_id', values: [userId], operator: 'wildcard' },
            ],
            first: 10,
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
      </>
    );
  }
}

UserHistory.propTypes = {
  t: PropTypes.func,
  userId: PropTypes.string,
};

export default compose(inject18n)(UserHistory);
