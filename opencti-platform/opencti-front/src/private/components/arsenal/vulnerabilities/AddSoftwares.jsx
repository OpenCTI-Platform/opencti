import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSoftwaresLines, { addSoftwaresLinesQuery } from './AddSoftwaresLines';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import Drawer from '../../common/drawer/Drawer';

const styles = (theme) => ({
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

class AddSoftwares extends Component {
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
    const { t, classes, vulnerability, vulnerabilitySoftwares, relationshipType } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
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
          title={t('Add software')}
          header={(
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          )}
        >
          <QueryRenderer
            query={addSoftwaresLinesQuery}
            variables={{ ...paginationOptions, count: 25 }}
            render={({ props }) => {
              return (
                <AddSoftwaresLines
                  vulnerability={vulnerability}
                  vulnerabilitySoftwares={vulnerabilitySoftwares}
                  relationshipType={relationshipType}
                  data={props}
                />
              );
            }}
          />
        </Drawer>
        <StixCyberObservableCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={{ ...paginationOptions, types: ['Software'] }}
          paginationKey="Pagination_stixCyberObservables"
          type="Software"
        />
      </div>
    );
  }
}

AddSoftwares.propTypes = {
  vulnerability: PropTypes.object,
  vulnerabilitySoftwares: PropTypes.array,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(AddSoftwares);
