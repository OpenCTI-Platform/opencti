import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import {
  AspectRatio,
  FilterListOutlined,
  AccountBalanceOutlined,
  DeleteOutlined,
  LinkOutlined,
  CenterFocusStrongOutlined,
  EditOutlined,
  InfoOutlined,
} from '@material-ui/icons';
import { Video3D, SelectAll } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import Drawer from '@material-ui/core/Drawer';
import Popover from '@material-ui/core/Popover';
import Toolbar from '@material-ui/core/Toolbar';
import inject18n from '../../../../components/i18n';
import ContainerAddStixCoreObjects from '../../common/containers/ContainerAddStixCoreObjects';
import StixCoreRelationshipCreation from '../../common/stix_core_relationships/StixCoreRelationshipCreation';
import { dateFormat } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import StixCoreRelationshipEdition from '../../common/stix_core_relationships/StixCoreRelationshipEdition';
import StixDomainObjectEdition from '../../common/stix_domain_objects/StixDomainObjectEdition';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '0 30px 0 190px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
});

class ReportKnowledgeGraphBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openStixCoreObjectsTypes: false,
      anchorElStixCoreObjectsTypes: null,
      openMarkedBy: false,
      anchorElMarkedBy: null,
      openCreatedBy: false,
      anchorElCreatedBy: null,
      openCreatedRelation: false,
      relationReversed: false,
      openEditRelation: false,
      openEditEntity: false,
    };
  }

  handleOpenStixCoreObjectsTypes(event) {
    this.setState({
      openStixCoreObjectsTypes: true,
      anchorElStixCoreObjectsTypes: event.currentTarget,
    });
  }

  handleCloseStixCoreObjectsTypes() {
    this.setState({
      openStixCoreObjectsTypes: false,
      anchorElStixCoreObjectsTypes: null,
    });
  }

  handleOpenCreatedBy(event) {
    this.setState({
      openCreatedBy: true,
      anchorElCreatedBy: event.currentTarget,
    });
  }

  handleCloseCreatedBy() {
    this.setState({ openCreatedBy: false, anchorElCreatedBy: null });
  }

  handleOpenMarkedBy(event) {
    this.setState({
      openMarkedBy: true,
      anchorElMarkedBy: event.currentTarget,
    });
  }

  handleCloseMarkedBy() {
    this.setState({ openMarkedBy: false, anchorElMarkedBy: null });
  }

  handleOpenCreateRelationship() {
    this.setState({ openCreatedRelation: true });
  }

  handleCloseCreateRelationship() {
    this.setState({ openCreatedRelation: false });
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
  }

  handleOpenEditItem() {
    if (
      this.props.numberOfSelectedNodes === 1
      && !this.props.selectedNodes[0].relationship_type
    ) {
      this.setState({ openEditEntity: true });
    } else if (
      this.props.numberOfSelectedLinks === 1
      || this.props.selectedNodes[0].relationship_type
    ) {
      this.setState({ openEditRelation: true });
    }
  }

  handleCloseEntityEdition() {
    this.setState({ openEditEntity: false });
    this.props.handleCloseEntityEdition(
      R.propOr(null, 'id', this.props.selectedNodes[0]),
    );
  }

  handleCloseRelationEdition() {
    this.setState({ openEditRelation: false });
    this.props.handleCloseRelationEdition(
      R.propOr(null, 'id', this.props.selectedLinks[0]),
    );
  }

  render() {
    const {
      t,
      classes,
      currentMode3D,
      currentCreatedBy,
      currentMarkedBy,
      currentStixCoreObjectsTypes,
      handleToggle3DMode,
      handleToggleCreatedBy,
      handleToggleMarkedBy,
      handleToggleStixCoreObjectType,
      handleZoomToFit,
      stixCoreObjectsTypes,
      createdBy,
      markedBy,
      report,
      onAdd,
      onDelete,
      handleDeleteSelected,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      selectedNodes,
      selectedLinks,
      lastLinkFirstSeen,
      lastLinkLastSeen,
      onAddRelation,
      handleSelectAll,
    } = this.props;
    const {
      openStixCoreObjectsTypes,
      anchorElStixCoreObjectsTypes,
      openMarkedBy,
      anchorElMarkedBy,
      openCreatedBy,
      anchorElCreatedBy,
      openCreatedRelation,
      relationReversed,
      openEditRelation,
      openEditEntity,
    } = this.state;
    const viewEnabled = (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 0 && numberOfSelectedLinks === 1);
    let viewLink = null;
    if (viewEnabled) {
      if (numberOfSelectedNodes === 1) {
        if (selectedNodes[0].relationship_type) {
          viewLink = `${resolveLink(selectedNodes[0].fromType)}/${
            selectedNodes[0].fromId
          }/knowledge/relations/${selectedNodes[0].id}`;
        } else {
          viewLink = `${resolveLink(selectedNodes[0].entity_type)}/${
            selectedNodes[0].id
          }`;
        }
      } else if (numberOfSelectedLinks === 1) {
        const remoteRelevant = selectedLinks[0].source.relationship_type
          ? selectedLinks[0].target
          : selectedLinks[0].source;
        viewLink = `${resolveLink(remoteRelevant.entity_type)}/${
          remoteRelevant.id
        }/knowledge/relations/${selectedLinks[0].id}`;
      }
    }
    const editionEnabled = (numberOfSelectedNodes === 1
        && numberOfSelectedLinks === 0
        && !selectedNodes[0].isObservable)
      || (numberOfSelectedNodes === 0 && numberOfSelectedLinks === 1);
    const relationEnabled = (numberOfSelectedNodes === 2 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1);
    let relationFrom = null;
    let relationTo = null;
    if (numberOfSelectedNodes === 2) {
      relationFrom = relationReversed ? selectedNodes[1] : selectedNodes[0];
      relationTo = relationReversed ? selectedNodes[0] : selectedNodes[1];
    } else if (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1) {
      relationFrom = relationReversed ? selectedNodes[0] : selectedLinks[0];
      relationTo = relationReversed ? selectedLinks[0] : selectedNodes[0];
    }
    return (
      <Drawer
        anchor="bottom"
        variant="permanent"
        classes={{ paper: classes.bottomNav }}
      >
        <Toolbar style={{ minHeight: 54 }}>
          <div style={{ position: 'absolute', left: 0 }}>
            <Tooltip title={t('Toggle 3D mode')}>
              <span>
                <IconButton
                  color={currentMode3D ? 'secondary' : 'primary'}
                  onClick={handleToggle3DMode.bind(this)}
                >
                  <Video3D />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t('Fit graph to canvas')}>
              <span>
                <IconButton
                  color="primary"
                  onClick={handleZoomToFit.bind(this)}
                >
                  <AspectRatio />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t('Filter entity types')}>
              <span>
                <IconButton
                  color="primary"
                  onClick={this.handleOpenStixCoreObjectsTypes.bind(this)}
                >
                  <FilterListOutlined />
                </IconButton>
              </span>
            </Tooltip>
            <Popover
              classes={{ paper: classes.container }}
              open={openStixCoreObjectsTypes}
              anchorEl={anchorElStixCoreObjectsTypes}
              onClose={this.handleCloseStixCoreObjectsTypes.bind(this)}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'center',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'center',
              }}
            >
              <List>
                {stixCoreObjectsTypes.map((stixCoreObjectType) => (
                  <ListItem
                    key={stixCoreObjectType}
                    role={undefined}
                    dense={true}
                    button={true}
                    onClick={handleToggleStixCoreObjectType.bind(
                      this,
                      stixCoreObjectType,
                    )}
                  >
                    <ListItemIcon style={{ minWidth: 40 }}>
                      <Checkbox
                        edge="start"
                        checked={currentStixCoreObjectsTypes.includes(
                          stixCoreObjectType,
                        )}
                        disableRipple={true}
                      />
                    </ListItemIcon>
                    <ListItemText primary={t(`entity_${stixCoreObjectType}`)} />
                  </ListItem>
                ))}
              </List>
            </Popover>
            <Tooltip title={t('Filter marking definitions')}>
              <span>
                <IconButton
                  color="primary"
                  onClick={this.handleOpenMarkedBy.bind(this)}
                >
                  <CenterFocusStrongOutlined />
                </IconButton>
              </span>
            </Tooltip>
            <Popover
              classes={{ paper: classes.container }}
              open={openMarkedBy}
              anchorEl={anchorElMarkedBy}
              onClose={this.handleCloseMarkedBy.bind(this)}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'center',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'center',
              }}
            >
              <List>
                {markedBy.map((markingDefinition) => (
                  <ListItem
                    key={markingDefinition.id}
                    role={undefined}
                    dense={true}
                    button={true}
                    onClick={handleToggleMarkedBy.bind(
                      this,
                      markingDefinition.id,
                    )}
                  >
                    <ListItemIcon style={{ minWidth: 40 }}>
                      <Checkbox
                        edge="start"
                        checked={currentMarkedBy.includes(markingDefinition.id)}
                        disableRipple={true}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={truncate(markingDefinition.definition, 20)}
                    />
                  </ListItem>
                ))}
              </List>
            </Popover>
            <Tooltip title={t('Filter authors (created by)')}>
              <span>
                <IconButton
                  color="primary"
                  onClick={this.handleOpenCreatedBy.bind(this)}
                >
                  <AccountBalanceOutlined />
                </IconButton>
              </span>
            </Tooltip>
            <Popover
              classes={{ paper: classes.container }}
              open={openCreatedBy}
              anchorEl={anchorElCreatedBy}
              onClose={this.handleCloseCreatedBy.bind(this)}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'center',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'center',
              }}
            >
              <List>
                {createdBy.map((createdByRef) => (
                  <ListItem
                    key={createdBy.id}
                    role={undefined}
                    dense={true}
                    button={true}
                    onClick={handleToggleCreatedBy.bind(this, createdByRef.id)}
                  >
                    <ListItemIcon style={{ minWidth: 40 }}>
                      <Checkbox
                        edge="start"
                        checked={currentCreatedBy.includes(createdByRef.id)}
                        disableRipple={true}
                      />
                    </ListItemIcon>
                    <ListItemText primary={createdByRef.name} />
                  </ListItem>
                ))}
              </List>
            </Popover>
            <Tooltip title={t('Select all nodes')}>
              <span>
                <IconButton
                  color="primary"
                  onClick={handleSelectAll.bind(this)}
                >
                  <SelectAll />
                </IconButton>
              </span>
            </Tooltip>
          </div>
          {report && (
            <div style={{ position: 'absolute', right: 0, display: 'flex' }}>
              <ContainerAddStixCoreObjects
                containerId={report.id}
                containerStixCoreObjects={report.objects.edges}
                knowledgeGraph={true}
                defaultCreatedBy={R.propOr(null, 'createdBy', report)}
                defaultMarkingDefinitions={R.map(
                  (n) => n.node,
                  R.pathOr([], ['objectMarking', 'edges'], report),
                )}
                targetStixCoreObjectTypes={[
                  'Stix-Domain-Object',
                  'Stix-Cyber-Observable',
                ]}
                onAdd={onAdd}
                onDelete={onDelete}
              />
              <Tooltip title={t('View the item')}>
                <span>
                  <IconButton
                    color="primary"
                    component={Link}
                    target="_blank"
                    to={viewLink}
                    disabled={!viewEnabled}
                  >
                    <InfoOutlined />
                  </IconButton>
                </span>
              </Tooltip>
              <Tooltip title={t('Edit the selected item')}>
                <span>
                  <IconButton
                    color="primary"
                    onClick={this.handleOpenEditItem.bind(this)}
                    disabled={!editionEnabled}
                  >
                    <EditOutlined />
                  </IconButton>
                </span>
              </Tooltip>
              <StixDomainObjectEdition
                open={openEditEntity}
                stixDomainObjectId={R.propOr(null, 'id', selectedNodes[0])}
                handleClose={this.handleCloseEntityEdition.bind(this)}
              />
              <StixCoreRelationshipEdition
                open={openEditRelation}
                stixCoreRelationshipId={
                  R.propOr(null, 'id', selectedNodes[0])
                  || R.propOr(null, 'id', selectedLinks[0])
                }
                handleClose={this.handleCloseRelationEdition.bind(this)}
              />
              <Tooltip title={t('Create a relationship')}>
                <span>
                  <IconButton
                    color="primary"
                    onClick={this.handleOpenCreateRelationship.bind(this)}
                    disabled={!relationEnabled}
                  >
                    <LinkOutlined />
                  </IconButton>
                </span>
              </Tooltip>
              <StixCoreRelationshipCreation
                open={openCreatedRelation}
                from={relationFrom}
                to={relationTo}
                firstSeen={lastLinkFirstSeen || dateFormat(report.published)}
                lastSeen={lastLinkLastSeen || dateFormat(report.published)}
                weight={report.confidence}
                handleClose={this.handleCloseCreateRelationship.bind(this)}
                handleResult={onAddRelation}
                handleReverseRelation={this.handleReverseRelation.bind(this)}
                defaultCreatedBy={R.propOr(null, 'createdBy', report)}
                defaultMarkingDefinitions={R.map(
                  (n) => n.node,
                  R.pathOr([], ['objectMarking', 'edges'], report),
                )}
              />
              <Tooltip title={t('Remove selected items')}>
                <span>
                  <IconButton
                    color="primary"
                    onClick={handleDeleteSelected.bind(this)}
                    disabled={
                      numberOfSelectedNodes === 0 && numberOfSelectedLinks === 0
                    }
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            </div>
          )}
        </Toolbar>
      </Drawer>
    );
  }
}

ReportKnowledgeGraphBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  report: PropTypes.object,
  handleToggle3DMode: PropTypes.func,
  currentMode3D: PropTypes.bool,
  handleToggleTreeMode: PropTypes.func,
  currentModeTree: PropTypes.bool,
  handleZoomToFit: PropTypes.func,
  handleToggleStixCoreObjectType: PropTypes.func,
  stixCoreObjectsTypes: PropTypes.array,
  currentStixCoreObjectsTypes: PropTypes.array,
  handleToggleMarkedBy: PropTypes.func,
  markedBy: PropTypes.array,
  currentMarkedBy: PropTypes.array,
  handleToggleCreatedBy: PropTypes.func,
  createdBy: PropTypes.array,
  currentCreatedBy: PropTypes.array,
  selectedNodes: PropTypes.array,
  selectedLinks: PropTypes.array,
  numberOfSelectedNodes: PropTypes.number,
  numberOfSelectedLinks: PropTypes.number,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  onAddRelation: PropTypes.func,
  handleDeleteSelected: PropTypes.func,
  lastLinkFirstSeen: PropTypes.string,
  lastLinkLastSeen: PropTypes.string,
  handleCloseEntityEdition: PropTypes.func,
  handleCloseRelationEdition: PropTypes.func,
  handleSelectAll: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(ReportKnowledgeGraphBar);
