import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubAttackPatternsLines, { addSubAttackPatternsLinesQuery } from './AddSubAttackPatternsLines';
import AttackPatternCreation from './AttackPatternCreation';

class AddSubAttackPattern extends Component {
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
    const { t, attackPattern, attackPatternSubAttackPatterns } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add sub attack patterns')}
          header={(
            <>
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
              />
              <AttackPatternCreation
                display={this.state.open}
                contextual={true}
                inputValue={this.state.search}
                paginationOptions={paginationOptions}
              />
            </>
          )}
        >
          <>
            <QueryRenderer
              query={addSubAttackPatternsLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                return (
                  <AddSubAttackPatternsLines
                    attackPattern={attackPattern}
                    attackPatternSubAttackPatterns={
                      attackPatternSubAttackPatterns
                    }
                    data={props}
                  />
                );
              }}
            />
          </>
        </Drawer>
      </>
    );
  }
}

AddSubAttackPattern.propTypes = {
  attackPattern: PropTypes.object,
  attackPatternSubAttackPatterns: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n)(AddSubAttackPattern);
