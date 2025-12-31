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
import LocationCreation from '../../common/location/LocationCreation';
import AddLocationsThreatActorGroupLines, { addLocationsThreatActorGroupLinesQuery } from './AddLocationsThreatActorGroupLines';
import { insertNode } from '../../../../utils/store';

const styles = () => ({
  createButton: {
    float: 'left',
    marginTop: '-10px',
  },
  search: {
    marginLeft: 'auto',
    marginRight: ' 20px',
  },
});

class AddLocationsThreatActorGroup extends Component {
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
    const { t, classes, threatActorGroup, threatActorGroupLocations } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    const updater = (store) => insertNode(
      store,
      'Pagination_threatActorGroup_locations',
      paginationOptions,
      'locationAdd',
    );
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
          title={t('Add locations')}
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
            query={addLocationsThreatActorGroupLinesQuery}
            variables={{
              search: this.state.search,
              count: 100,
            }}
            render={({ props }) => {
              return (
                <AddLocationsThreatActorGroupLines
                  threatActorGroup={threatActorGroup}
                  threatActorGroupLocations={threatActorGroupLocations}
                  data={props}
                />
              );
            }}
          />
        </Drawer>
        <LocationCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
          updater={updater}
        />
      </>
    );
  }
}

AddLocationsThreatActorGroup.propTypes = {
  threatActorGroup: PropTypes.object,
  threatActorGroupLocations: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AddLocationsThreatActorGroup);
