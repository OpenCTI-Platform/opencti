import {
  AccountBalanceOutlined,
  AspectRatioOutlined,
  CenterFocusStrongOutlined,
  DateRangeOutlined,
  DeleteOutlined,
  EditOutlined,
  FilterAltOffOutlined,
  FilterListOutlined,
  GestureOutlined,
  LinkOutlined,
  OpenWithOutlined,
  ScatterPlotOutlined,
  Undo,
} from '@mui/icons-material';
import Badge from '@mui/material/Badge';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Divider from '@mui/material/Divider';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import LinearProgress from '@mui/material/LinearProgress';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Popover from '@mui/material/Popover';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { AutoFix, FamilyTree, SelectAll, SelectGroup, SelectionDrag, Video3d } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { Component } from 'react';
import TimeRange from 'react-timeline-range-slider';
import { ResponsiveContainer, Scatter, ScatterChart, YAxis, ZAxis } from 'recharts';
import { getPreExpansionStateList } from './utils/investigationStorage';
import InvestigationAddStixCoreObjects from './InvestigationAddStixCoreObjects';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { parseDomain } from '../../../../utils/Graph';
import { INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { truncate } from '../../../../utils/String';
import { dateFormat } from '../../../../utils/Time';
import StixCoreRelationshipCreation from '../../common/stix_core_relationships/StixCoreRelationshipCreation';
import StixCoreRelationshipEdition from '../../common/stix_core_relationships/StixCoreRelationshipEdition';
import StixDomainObjectEdition from '../../common/stix_domain_objects/StixDomainObjectEdition';
import StixCyberObservableEdition from '../../observations/stix_cyber_observables/StixCyberObservableEdition';
import { UserContext } from '../../../../utils/hooks/useAuth';
import StixSightingRelationshipEdition from '../../events/stix_sighting_relationships/StixSightingRelationshipEdition';

const styles = () => ({
  bottomNav: {
    zIndex: 1,
    display: 'flex',
    overflow: 'hidden',
  },
  divider: {
    display: 'inline-block',
    verticalAlign: 'middle',
    height: '100%',
    margin: '0 5px 0 5px',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class InvestigationGraphBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openStixCoreObjectsTypes: false,
      anchorElStixCoreObjectsTypes: null,
      openMarkedBy: false,
      anchorElMarkedBy: null,
      openCreatedBy: false,
      anchorElCreatedBy: null,
      openSelectByType: false,
      anchorElSelectByType: null,
      openEditRelation: false,
      openEditSighting: false,
      openEditDomainObject: false,
      openEditObservable: false,
      openExpandElements: false,
      displayRemove: false,
      relationReversed: false,
      openCreatedRelation: false,
    };
  }

  componentDidUpdate(prevProps) {
    if (prevProps.openCreatedRelation === false && this.props.openCreatedRelation) {
      this.setState({ openCreatedRelation: true });
    }
  }

  handleOpenRemove() {
    this.setState({ displayRemove: true });
  }

  handleCloseRemove() {
    this.setState({ displayRemove: false });
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
    this.props.handleCloseRelationCreation();
  }

  handleOpenSelectByType(event) {
    this.setState({
      openSelectByType: true,
      anchorElSelectByType: event.currentTarget,
    });
  }

  handleCloseSelectByType() {
    this.setState({
      openSelectByType: false,
      anchorElSelectByType: null,
    });
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
  }

  handleOpenEditItem() {
    if (
      this.props.numberOfSelectedNodes === 1
      && !this.props.selectedNodes[0].relationship_type
      && !this.props.selectedNodes[0].parent_types.includes(
        'Stix-Cyber-Observable',
      )
    ) {
      this.setState({ openEditDomainObject: true });
    } else if (
      this.props.numberOfSelectedNodes === 1
      && !this.props.selectedNodes[0].relationship_type
      && this.props.selectedNodes[0].parent_types.includes('Stix-Cyber-Observable')
    ) {
      this.setState({ openEditObservable: true });
    } else if (
      (this.props.numberOfSelectedLinks === 1
        && this.props.selectedLinks[0].entity_type
        === 'stix-sighting-relationship')
      || (this.props.selectedNodes[0]
        && this.props.selectedNodes[0].relationship_type
        && this.props.selectedNodes[0].parent_types.includes(
          'stix-sighting-relationship',
        ))
    ) {
      this.setState({ openEditSighting: true });
    } else if (
      this.props.numberOfSelectedLinks === 1
      || this.props.selectedNodes[0].relationship_type
    ) {
      this.setState({ openEditRelation: true });
    }
  }

  handleCloseDomainObjectEdition() {
    this.setState({ openEditDomainObject: false });
    this.props.handleCloseEntityEdition(
      this.props.selectedNodes[0]?.id ?? null,
    );
  }

  handleCloseObservableEdition() {
    this.setState({ openEditObservable: false });
    this.props.handleCloseEntityEdition(
      this.props.selectedNodes[0]?.id ?? null,
    );
  }

  handleCloseRelationEdition() {
    this.setState({ openEditRelation: false });
    this.props.handleCloseRelationEdition(
      this.props.selectedLinks[0]?.id ?? null,
    );
  }

  handleCloseSightingEdition() {
    this.setState({ openEditSighting: false });
    this.props.handleCloseSightingEdition(
      this.props.selectedLinks[0]?.id ?? null,
    );
  }

  handleSelectByType(type) {
    this.props.handleSelectByType(type);
    this.handleCloseSelectByType();
  }

  render() {
    const {
      t,
      classes,
      currentMode3D,
      currentModeTree,
      currentModeFixed,
      currentCreatedBy,
      currentMarkedBy,
      currentStixCoreObjectsTypes,
      currentSelectRectangleModeFree,
      currentSelectModeFree,
      selectModeFreeReady,
      handleToggle3DMode,
      handleToggleTreeMode,
      handleToggleFixedMode,
      handleToggleCreatedBy,
      handleToggleMarkedBy,
      handleToggleStixCoreObjectType,
      handleZoomToFit,
      handleToggleRectangleSelectModeFree,
      handleToggleSelectModeFree,
      stixCoreObjectsTypes,
      createdBy,
      markedBy,
      workspace,
      onAdd,
      onAddRelation,
      onDelete,
      handleDeleteSelected,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      selectedNodes,
      selectedLinks,
      handleSelectAll,
      handleResetLayout,
      displayProgress,
      displayTimeRange,
      timeRangeInterval,
      selectedTimeRangeInterval,
      handleToggleDisplayTimeRange,
      handleTimeRangeChange,
      timeRangeValues,
      theme,
      lastLinkFirstSeen,
      lastLinkLastSeen,
      handleOpenExpandElements,
      navOpen,
      resetAllFilters,
      handleOpenRollBackToPreExpansionStateDialog,
    } = this.props;
    const {
      openStixCoreObjectsTypes,
      anchorElStixCoreObjectsTypes,
      openMarkedBy,
      anchorElMarkedBy,
      openCreatedBy,
      anchorElCreatedBy,
      openSelectByType,
      anchorElSelectByType,
      openEditRelation,
      openEditSighting,
      openEditDomainObject,
      openEditObservable,
      relationReversed,
      openCreatedRelation,
    } = this.state;
    const isInferred = selectedNodes.filter((n) => n.inferred).length > 0
      || selectedLinks.filter((n) => n.inferred).length > 0;
    const editionEnabled = (!isInferred
        && numberOfSelectedNodes === 1
        && numberOfSelectedLinks === 0
        && selectedNodes.length === 1
        && !selectedNodes[0].parent_types.includes('Stix-Meta-Object'))
      || (!isInferred
        && numberOfSelectedNodes === 0
        && numberOfSelectedLinks === 1
        && selectedLinks.length === 1
        && !selectedLinks[0].parent_types.includes('stix-ref-relationship'));
    const expandEnabled = numberOfSelectedNodes > 0;
    const fromSelectedTypes = numberOfSelectedNodes >= 2 && selectedNodes.length >= 2
      ? R.uniq(R.map((n) => n.entity_type, R.init(selectedNodes)))
      : [];
    const toSelectedTypes = numberOfSelectedNodes >= 2 && selectedNodes.length >= 2
      ? R.uniq(R.map((n) => n.entity_type, R.tail(selectedNodes)))
      : [];
    const relationEnabled = (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1);
    let relationFromObjects = null;
    let relationToObjects = null;
    if (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0) {
      relationFromObjects = relationReversed
        ? [R.last(selectedNodes)]
        : R.init(selectedNodes);
      relationToObjects = relationReversed
        ? R.init(selectedNodes)
        : [R.last(selectedNodes)];
    } else if (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0) {
      relationFromObjects = relationReversed
        ? R.tail(selectedNodes)
        : [R.head(selectedNodes)];
      relationToObjects = relationReversed
        ? [R.head(selectedNodes)]
        : R.tail(selectedNodes);
    } else if (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1) {
      relationFromObjects = relationReversed
        ? [selectedNodes[0]]
        : [selectedLinks[0]];
      relationToObjects = relationReversed
        ? [selectedLinks[0]]
        : [selectedNodes[0]];
    }
    const stixCoreObjectOrRelationshipId = (selectedNodes[0]?.id ?? null) || (selectedLinks[0]?.id ?? null);

    const isRollBackToLastPreExpansionStateDisabled = !getPreExpansionStateList();

    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
            PaperProps={{
              variant: 'elevation',
              elevation: 1,
              style: {
                bottom: bannerSettings.bannerHeightNumber,
              },
            }}
          >
            <div
              style={{
                height: displayTimeRange ? 134 : 54,
                verticalAlign: 'top',
                transition: 'height 0.2s linear',
              }}
            >
              <LinearProgress
                style={{
                  width: '100%',
                  height: 2,
                  position: 'absolute',
                  top: -1,
                  visibility: displayProgress ? 'visible' : 'hidden',
                }}
              />
              <div
                style={{
                  verticalAlign: 'top',
                  width: '100%',
                  height: 54,
                  paddingTop: 3,
                }}
              >
                <div
                  style={{
                    float: 'left',
                    marginLeft: navOpen ? 185 : 60,
                    height: '100%',
                    display: 'flex',
                  }}
                >
                  <Tooltip
                    title={
                      currentMode3D ? t('Disable 3D mode') : t('Enable 3D mode')
                    }
                  >
                    <span>
                      <IconButton
                        color={currentMode3D ? 'secondary' : 'primary'}
                        onClick={handleToggle3DMode.bind(this)}
                        size="large"
                      >
                        <Video3d />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip
                    title={
                      currentModeTree
                        ? t('Disable vertical tree mode')
                        : t('Enable vertical tree mode')
                    }
                  >
                    <span>
                      <IconButton
                        color={
                          currentModeTree === 'vertical'
                            ? 'secondary'
                            : 'primary'
                        }
                        onClick={handleToggleTreeMode.bind(this, 'vertical')}
                        disabled={currentModeFixed}
                        size="large"
                      >
                        <FamilyTree />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip
                    title={
                      currentModeTree
                        ? t('Disable horizontal tree mode')
                        : t('Enable horizontal tree mode')
                    }
                  >
                    <span>
                      <IconButton
                        color={
                          currentModeTree === 'horizontal'
                            ? 'secondary'
                            : 'primary'
                        }
                        onClick={handleToggleTreeMode.bind(this, 'horizontal')}
                        disabled={currentModeFixed}
                        size="large"
                      >
                        <FamilyTree style={{ transform: 'rotate(-90deg)' }} />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip
                    title={
                      currentModeFixed
                        ? t('Enable forces')
                        : t('Disable forces')
                    }
                  >
                    <span>
                      <IconButton
                        color={currentModeFixed ? 'primary' : 'secondary'}
                        onClick={handleToggleFixedMode.bind(this)}
                        size="large"
                      >
                        <ScatterPlotOutlined />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title={t('Fit graph to canvas')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={handleZoomToFit.bind(this)}
                        size="large"
                      >
                        <AspectRatioOutlined />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title={t('Unfix the nodes and re-apply forces')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={handleResetLayout.bind(this)}
                        disabled={currentModeFixed}
                        size="large"
                      >
                        <AutoFix />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Divider className={classes.divider} orientation="vertical" />
                  <Tooltip title={t('Free rectangle select')}>
                    <span>
                      <IconButton
                        color={
                          currentSelectRectangleModeFree
                            ? 'secondary'
                            : 'primary'
                        }
                        size="large"
                        onClick={handleToggleRectangleSelectModeFree.bind(this)}
                        disabled={currentMode3D}
                      >
                        <SelectionDrag />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title={t('Free select')}>
                    <IconButton
                      color={currentSelectModeFree ? 'secondary' : 'primary'}
                      size="large"
                      onClick={handleToggleSelectModeFree.bind(this)}
                      disabled={!selectModeFreeReady || currentMode3D}
                    >
                      <GestureOutlined />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('Select by entity type')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={this.handleOpenSelectByType.bind(this)}
                        size="large"
                      >
                        <SelectGroup />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Popover
                    classes={{ paper: classes.container }}
                    open={openSelectByType}
                    anchorEl={anchorElSelectByType}
                    onClose={this.handleCloseSelectByType.bind(this)}
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
                          onClick={this.handleSelectByType.bind(
                            this,
                            stixCoreObjectType,
                          )}
                        >
                          <ListItemText
                            primary={t(`entity_${stixCoreObjectType}`)}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Popover>
                  <Tooltip title={t('Select all nodes')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={handleSelectAll.bind(this)}
                        size="large"
                      >
                        <SelectAll />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Divider className={classes.divider} orientation="vertical" />
                  <Tooltip title={t('Display time range selector')}>
                    <span>
                      <IconButton
                        color={displayTimeRange ? 'secondary' : 'primary'}
                        onClick={handleToggleDisplayTimeRange.bind(this)}
                        size="large"
                      >
                        <DateRangeOutlined />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title={t('Filter entity types')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={this.handleOpenStixCoreObjectsTypes.bind(this)}
                        size="large"
                      >
                        <Badge
                          badgeContent={currentStixCoreObjectsTypes.length}
                          color="secondary"
                        >
                          <FilterListOutlined />
                        </Badge>
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
                              checked={
                                !currentStixCoreObjectsTypes.includes(
                                  stixCoreObjectType,
                                )
                              }
                              disableRipple={true}
                            />
                          </ListItemIcon>
                          <ListItemText
                            primary={t(`entity_${stixCoreObjectType}`)}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Popover>
                  <Tooltip title={t('Filter marking definitions')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={this.handleOpenMarkedBy.bind(this)}
                        size="large"
                      >
                        <Badge
                          badgeContent={currentMarkedBy.length}
                          color="secondary"
                        >
                          <CenterFocusStrongOutlined />
                        </Badge>
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
                              checked={
                                !currentMarkedBy.includes(markingDefinition.id)
                              }
                              disableRipple={true}
                            />
                          </ListItemIcon>
                          <ListItemText
                            primary={truncate(markingDefinition.definition, 20, false)}
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
                        size="large"
                      >
                        <Badge
                          badgeContent={currentCreatedBy.length}
                          color="secondary"
                        >
                          <AccountBalanceOutlined />
                        </Badge>
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
                          onClick={handleToggleCreatedBy.bind(
                            this,
                            createdByRef.id,
                          )}
                        >
                          <ListItemIcon style={{ minWidth: 40 }}>
                            <Checkbox
                              edge="start"
                              checked={
                                !currentCreatedBy.includes(createdByRef.id)
                              }
                              disableRipple={true}
                            />
                          </ListItemIcon>
                          <ListItemText primary={createdByRef.name} />
                        </ListItem>
                      ))}
                    </List>
                  </Popover>
                  {resetAllFilters && (
                    <Tooltip title={t('Clear all filters')}>
                      <span>
                        <IconButton
                          color="primary"
                          onClick={resetAllFilters.bind(this)}
                          size="large"
                        >
                          <FilterAltOffOutlined />
                        </IconButton>
                      </span>
                    </Tooltip>
                  )}
                  <Divider className={classes.divider} orientation="vertical" />
                  <div style={{ margin: '9px 0 0 10px' }}>
                    <SearchInput
                      variant="thin"
                      onSubmit={this.props.handleSearch.bind(this)}
                    />
                  </div>
                </div>
                {workspace && (
                  <Security
                    needs={[INVESTIGATION_INUPDATE]}
                    hasAccess={
                      workspace.currentUserAccessRight === 'admin'
                      || workspace.currentUserAccessRight === 'edit'
                    }
                  >
                    <div
                      style={{
                        float: 'right',
                        display: 'flex',
                        height: '100%',
                      }}
                    >
                      {onAdd && (
                        <InvestigationAddStixCoreObjects
                          workspaceId={workspace.id}
                          workspaceStixCoreObjects={workspace.objects.edges}
                          targetStixCoreObjectTypes={[
                            'Stix-Domain-Object',
                            'Stix-Cyber-Observable',
                          ]}
                          onAdd={onAdd}
                          onDelete={onDelete}
                        />
                      )}
                      <Tooltip title={t('Edit the selected item')}>
                        <span>
                          <IconButton
                            color="primary"
                            onClick={this.handleOpenEditItem.bind(this)}
                            disabled={!editionEnabled}
                            size="large"
                          >
                            <EditOutlined />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <StixDomainObjectEdition
                        open={openEditDomainObject}
                        stixDomainObjectId={selectedNodes[0]?.id ?? null}
                        handleClose={this.handleCloseDomainObjectEdition.bind(
                          this,
                        )}
                        noStoreUpdate={true}
                      />
                      <StixCyberObservableEdition
                        open={openEditObservable}
                        stixCyberObservableId={selectedNodes[0]?.id ?? null}
                        handleClose={this.handleCloseObservableEdition.bind(
                          this,
                        )}
                      />
                      {stixCoreObjectOrRelationshipId != null && (
                        <>
                          <StixCoreRelationshipEdition
                            open={openEditRelation}
                            stixCoreRelationshipId={
                              stixCoreObjectOrRelationshipId
                            }
                            handleClose={this.handleCloseRelationEdition.bind(
                              this,
                            )}
                            noStoreUpdate={true}
                            inGraph={true}
                          />
                          <StixSightingRelationshipEdition
                            open={openEditSighting}
                            stixSightingRelationshipId={
                              stixCoreObjectOrRelationshipId
                            }
                            handleClose={this.handleCloseSightingEdition.bind(
                              this,
                            )}
                            noStoreUpdate={true}
                            inGraph={true}
                          />
                        </>
                      )}
                      <Tooltip title={t('Restore the state of the graphic before the last expansion')}>
                        <span>
                          <IconButton
                            color="primary"
                            disabled={isRollBackToLastPreExpansionStateDisabled }
                            onClick={handleOpenRollBackToPreExpansionStateDialog}
                            size="large"
                          >
                            <Undo />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Tooltip title={t('Expand')}>
                        <span>
                          <IconButton
                            color="primary"
                            onClick={handleOpenExpandElements.bind(this)}
                            disabled={!expandEnabled}
                            size="large"
                          >
                            <OpenWithOutlined />
                          </IconButton>
                        </span>
                      </Tooltip>
                      {onAddRelation && (
                        <Tooltip title={t('Create a relationship')}>
                          <span>
                            <IconButton
                              color="primary"
                              onClick={this.handleOpenCreateRelationship.bind(
                                this,
                              )}
                              disabled={!relationEnabled}
                              size="large"
                            >
                              <LinkOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      {onAddRelation && (
                        <StixCoreRelationshipCreation
                          open={openCreatedRelation}
                          fromObjects={relationFromObjects}
                          toObjects={relationToObjects}
                          startTime={lastLinkFirstSeen || null}
                          stopTime={lastLinkLastSeen || null}
                          confidence={50}
                          handleClose={this.handleCloseCreateRelationship.bind(
                            this,
                          )}
                          handleResult={onAddRelation}
                          handleReverseRelation={this.handleReverseRelation.bind(
                            this,
                          )}
                        />
                      )}
                      <Tooltip title={t('Remove selected items')}>
                        <span>
                          <IconButton
                            color="primary"
                            onClick={this.handleOpenRemove.bind(this)}
                            disabled={
                              numberOfSelectedNodes === 0
                              && numberOfSelectedLinks === 0
                            }
                            size="large"
                          >
                            <DeleteOutlined />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Dialog
                        open={this.state.displayRemove}
                        PaperProps={{ elevation: 1 }}
                        keepMounted={true}
                        TransitionComponent={Transition}
                        onClose={this.handleCloseRemove.bind(this)}
                      >
                        <DialogContent>
                          <DialogContentText>
                            {t(
                              'Do you want to remove these elements from this investigation?',
                            )}
                          </DialogContentText>
                        </DialogContent>
                        <DialogActions>
                          <Button onClick={this.handleCloseRemove.bind(this)}>
                            {t('Cancel')}
                          </Button>
                          <Button
                            onClick={() => {
                              this.handleCloseRemove();
                              handleDeleteSelected();
                            }}
                            color="secondary"
                          >
                            {t('Remove')}
                          </Button>
                        </DialogActions>
                      </Dialog>
                    </div>
                  </Security>
                )}
              </div>
              <div className="clearfix" />
              <div
                style={{
                  height: '100%',
                  padding: navOpen
                    ? '30px 10px 0px 190px'
                    : '30px 10px 0px 65px',
                }}
              >
                <div
                  style={{
                    position: 'absolute',
                    width: '100%',
                    height: '100%',
                    bottom: -50,
                    left: navOpen ? 120 : 0,
                  }}
                >
                  <ResponsiveContainer width="100%" height={60}>
                    <ScatterChart
                      width="100%"
                      height={60}
                      margin={{
                        top: 32,
                        right: navOpen ? 150 : 20,
                        bottom: 0,
                        left: 0,
                      }}
                    >
                      <YAxis
                        type="number"
                        dataKey="index"
                        name="scatter"
                        height={10}
                        width={80}
                        tick={false}
                        tickLine={false}
                        axisLine={false}
                      />
                      <ZAxis
                        type="number"
                        dataKey="value"
                        range={[15, 200]}
                        domain={parseDomain(timeRangeValues)}
                      />
                      <Scatter
                        data={timeRangeValues}
                        fill={theme.palette.primary.main}
                      />
                    </ScatterChart>
                  </ResponsiveContainer>
                </div>
                <TimeRange
                  ticksNumber={15}
                  selectedInterval={selectedTimeRangeInterval}
                  timelineInterval={timeRangeInterval}
                  onUpdateCallback={() => null}
                  onChangeCallback={handleTimeRangeChange}
                  formatTick={dateFormat}
                  containerClassName="timerange"
                />
              </div>
            </div>
          </Drawer>
        )}
      </UserContext.Consumer>
    );
  }
}

InvestigationGraphBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  workspace: PropTypes.object,
  handleToggle3DMode: PropTypes.func,
  handleToggleTreeMode: PropTypes.func,
  currentMode3D: PropTypes.bool,
  handleToggleRectangleSelectModeFree: PropTypes.func,
  handleToggleSelectModeFree: PropTypes.func,
  currentModeTree: PropTypes.string,
  currentModeFixed: PropTypes.bool,
  currentSelectModeFree: PropTypes.bool,
  currentSelectRectangleModeFree: PropTypes.bool,
  selectModeFreeReady: PropTypes.bool,
  handleToggleFixedMode: PropTypes.func,
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
  elementsDates: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  onAddRelation: PropTypes.func,
  handleOpenExpandElements: PropTypes.func,
  handleCloseExpandElements: PropTypes.func,
  handleDeleteSelected: PropTypes.func,
  handleCloseEntityEdition: PropTypes.func,
  handleCloseRelationEdition: PropTypes.func,
  handleCloseSightingEdition: PropTypes.func,
  handleSelectAll: PropTypes.func,
  handleSelectByType: PropTypes.func,
  handleResetLayout: PropTypes.func,
  displayTimeRange: PropTypes.bool,
  handleToggleDisplayTimeRange: PropTypes.func,
  handleOpenRollBackToPreExpansionStateDialog: PropTypes.func,
  handleTimeRangeChange: PropTypes.func,
  timeRangeInterval: PropTypes.array,
  selectedTimeRangeInterval: PropTypes.array,
  timeRangeValues: PropTypes.array,
  theme: PropTypes.object,
  lastLinkFirstSeen: PropTypes.string,
  lastLinkLastSeen: PropTypes.string,
  navOpen: PropTypes.bool,
  openCreatedRelation: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(InvestigationGraphBar);
