import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddAttackPatternsLines, { addAttackPatternsLinesQuery } from './AddAttackPatternsLines';

class AddAttackPatterns extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const {
      t,
      courseOfAction,
      courseOfActionAttackPatterns,
      courseOfActionPaginationOptions,
    } = this.props;
    return (
      <div>
        <IconButton
          color="primary"
          aria-label="Attack Pattern"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add attack patterns')}
          subHeader={{
            left: [(
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
                key="searchInput"
              />
            )],
          }}
        >
          <QueryRenderer
            query={addAttackPatternsLinesQuery}
            variables={{
              search: this.state.search,
              count: 20,
            }}
            render={({ props }) => {
              return (
                <AddAttackPatternsLines
                  courseOfAction={courseOfAction}
                  courseOfActionAttackPatterns={courseOfActionAttackPatterns}
                  courseOfActionPaginationOptions={
                    courseOfActionPaginationOptions
                  }
                  data={props}
                />
              );
            }}
          />
        </Drawer>
      </div>
    );
  }
}

AddAttackPatterns.propTypes = {
  courseOfAction: PropTypes.object,
  courseOfActionAttackPatterns: PropTypes.array,
  courseOfActionPaginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n)(AddAttackPatterns);
