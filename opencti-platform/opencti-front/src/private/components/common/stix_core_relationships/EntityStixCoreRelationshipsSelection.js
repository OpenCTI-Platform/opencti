import React, { Component } from 'react';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import * as PropTypes from 'prop-types';
import Grid from '@material-ui/core/Grid';
import Drawer from '@material-ui/core/Drawer';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from './EntityStixCoreRelationships';

const styles = (theme) => ({
  container: {
    marginTop: 15,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

class EntityStixCoreRelationshipsSelection extends Component {
  constructor(props) {
    super(props);

    const { targetStixCoreRelationshipTypes } = props;
    const defaultRelationshipType = targetStixCoreRelationshipTypes[0];

    this.state = {
      openToType: false,
      selectedRelationshipType: defaultRelationshipType,
    };
  }

  handleOpenToType() {
    this.setState({ openToType: true });
  }

  handleCloseToType() {
    this.setState({ openToType: false });
  }

  handleChangeRelationshipType(event) {
    const { value } = event.target;

    return this.setState({ openToType: false, selectedRelationshipType: value });
  }

  renderMenuItems() {
    const { targetStixCoreRelationshipTypes } = this.props;

    return targetStixCoreRelationshipTypes.map(
      (relationshipType) => this.renderMenuItem(relationshipType),
    );
  }

  renderMenuItem(relationshipType) {
    return (
      <MenuItem key={relationshipType} value={relationshipType}>
        {this.getRelationshipTypeLabel(relationshipType)}
      </MenuItem>
    );
  }

  getRelationshipTypeLabel(relationshipType) {
    const { t } = this.props;

    return t(`relationship_${relationshipType}`);
  }

  renderSelectedValue(relationshipType) {
    const { classes } = this.props;

    return (
      <div className={classes.chips}>
        <Chip
          key={relationshipType}
          label={this.getRelationshipTypeLabel(relationshipType)}
          className={classes.chip}
        />
      </div>
    );
  }

  renderSelection() {
    const { selectedRelationshipType, openToType } = this.state;

    return (
      <Select
        style={{ height: 50, marginRight: 15 }}
        value={selectedRelationshipType}
        open={openToType}
        onClose={this.handleCloseToType.bind(this)}
        onOpen={this.handleOpenToType.bind(this)}
        onChange={this.handleChangeRelationshipType.bind(this)}
        input={<Input id="entities" />}
        renderValue={this.renderSelectedValue.bind(this)}
      >
        {this.renderMenuItems()}
      </Select>
    );
  }

  renderBottomMenu() {
    const { classes } = this.props;

    return (
      <div className={classes.container}>
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            {this.renderSelection()}
          </Grid>
        </Drawer>
      </div>
    );
  }

  render() {
    const { entityId, entityLink, targetStixDomainObjectTypes } = this.props;
    const { selectedRelationshipType } = this.state;

    return (
      <div>
        <EntityStixCoreRelationships
          entityId={entityId}
          relationshipType={selectedRelationshipType}
          targetStixDomainObjectTypes={targetStixDomainObjectTypes}
          entityLink={entityLink}
          isRelationReversed={true}
          noBottomBar={true}
          noState={true}
        />
        <div>{this.renderBottomMenu()}</div>
      </div>
    );
  }
}

EntityStixCoreRelationshipsSelection.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  targetStixCoreRelationshipTypes: PropTypes.array,
  targetStixDomainObjectTypes: PropTypes.array,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(EntityStixCoreRelationshipsSelection);
