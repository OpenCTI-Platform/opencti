import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Add, Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddLocationsThreatActorIndividualLines, {
  addLocationsThreatActorIndividualLinesQuery,
} from './AddLocationsThreatActorIndividualLines';
import LocationCreation from '../../common/location/LocationCreation';

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
    float: 'right',
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
    const { t, classes, threatActorIndividual, threatActorIndividualLocations } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <>
        <IconButton
          color="secondary"
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
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add locations')}
            </Typography>
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.container}>
            <QueryRenderer
              query={addLocationsThreatActorIndividualLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                return (
                  <AddLocationsThreatActorIndividualLines
                    threatActorIndividual={threatActorIndividual}
                    threatActorIndividualLocations={threatActorIndividualLocations}
                    data={props}
                  />
                );
              }}
            />
          </div>
        </Drawer>
        <LocationCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        />
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

export default compose(inject18n, withStyles(styles))(AddLocationsThreatActorIndividual);
