import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubAttackPatternsLines, { addSubAttackPatternsLinesQuery } from './AddSubAttackPatternsLines';
import AttackPatternCreation from './AttackPatternCreation';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    marginLeft: 'auto',
    marginRight: ' 20px',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
  },
});

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
    const { t, classes, attackPattern, attackPatternSubAttackPatterns } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
          classes={{ root: classes.createButton }}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add sub attack patterns')}
          header={(
            <div
              style={{
                marginLeft: 'auto',
                marginRight: '20px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-end',
              }}
            >
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
            </div>
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

export default compose(inject18n, withStyles(styles))(AddSubAttackPattern);
