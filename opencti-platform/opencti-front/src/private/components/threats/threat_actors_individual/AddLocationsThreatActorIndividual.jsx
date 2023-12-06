import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddLocationsThreatActorIndividualLines, { addLocationsThreatActorIndividualLinesQuery } from './AddLocationsThreatActorIndividualLines';
import LocationCreation from '../../common/location/LocationCreation';
import { insertNode } from '../../../../utils/store';

const styles = () => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  search: {
    marginLeft: 'auto',
    marginRight: '20px',
    display: 'flex',
  },
});

class AddLocationsThreatActorIndividual extends Component {
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
      classes,
      threatActorIndividual,
      threatActorIndividualLocations,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    const updater = (store) => insertNode(
      store,
      'Pagination_threatActorIndividual_locations',
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
          size="large"
          style={{ marginTop: -15 }}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add locations')}
          header={
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
              />
              <LocationCreation
                display={this.state.open}
                contextual={true}
                inputValue={this.state.search}
                paginationOptions={paginationOptions}
                updater={updater}
              />
            </div>
          }
        >
          <QueryRenderer
            query={addLocationsThreatActorIndividualLinesQuery}
            variables={{
              search: this.state.search,
              count: 50,
            }}
            render={({ props }) => {
              return (
                <AddLocationsThreatActorIndividualLines
                  threatActorIndividual={threatActorIndividual}
                  threatActorIndividualLocations={
                    threatActorIndividualLocations
                  }
                  data={props}
                />
              );
            }}
          />
        </Drawer>
      </>
    );
  }
}

AddLocationsThreatActorIndividual.propTypes = {
  threatActorIndividual: PropTypes.object,
  threatActorIndividualLocations: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AddLocationsThreatActorIndividual);
