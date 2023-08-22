import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
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
  ReadMoreOutlined,
  ScatterPlotOutlined,
  VisibilityOutlined,
} from '@mui/icons-material';
import {
  AutoFix,
  FamilyTree,
  SelectAll,
  SelectGroup,
  SelectionDrag,
  Video3d,
} from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import Popover from '@mui/material/Popover';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Divider from '@mui/material/Divider';
import TimeRange from 'react-timeline-range-slider';
import {
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  YAxis,
  ZAxis,
} from 'recharts';
import Badge from '@mui/material/Badge';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import inject18n from '../../../../components/i18n';
import ContainerAddStixCoreObjects from '../../common/containers/ContainerAddStixCoreObjects';
import StixCoreRelationshipCreation from '../../common/stix_core_relationships/StixCoreRelationshipCreation';
import { dateFormat } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import StixCoreRelationshipEdition from '../../common/stix_core_relationships/StixCoreRelationshipEdition';
import StixDomainObjectEdition from '../../common/stix_domain_objects/StixDomainObjectEdition';
import { parseDomain } from '../../../../utils/Graph';
import StixSightingRelationshipCreation from '../../events/stix_sighting_relationships/StixSightingRelationshipCreation';
import StixSightingRelationshipEdition from '../../events/stix_sighting_relationships/StixSightingRelationshipEdition';
import SearchInput from '../../../../components/SearchInput';
import StixNestedRefRelationshipCreation from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation';
import StixNestedRefRelationshipEdition from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipEdition';
import StixCyberObservableEdition from '../../observations/stix_cyber_observables/StixCyberObservableEdition';
import { isStixNestedRefRelationship } from '../../../../utils/Relation';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import { UserContext } from '../../../../utils/hooks/useAuth';

const styles = () => ({
  bottomNav: {
    zIndex: 1000,
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
      openSelectByType: false,
      anchorElSelectByType: null,
      openCreatedRelation: false,
      openCreatedSighting: false,
      openCreatedNested: false,
      relationReversed: false,
      sightingReversed: false,
      nestedReversed: false,
      openEditRelation: false,
      openEditSighting: false,
      openEditNested: false,
      openEditDomainObject: false,
      openEditObservable: false,
      displayRemove: false,
      deleteObject: false,
    };
  }

  handleOpenRemove() {
    this.setState({ displayRemove: true });
  }

  handleCloseRemove() {
    this.setState({ displayRemove: false, deleteObject: false });
  }

  handleToggleDeleteObject() {
    this.setState({ deleteObject: !this.state.deleteObject });
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

  handleOpenCreateSighting() {
    this.setState({ openCreatedSighting: true });
  }

  handleCloseCreateSighting() {
    this.setState({ openCreatedSighting: false });
  }

  handleReverseSighting() {
    this.setState({ sightingReversed: !this.state.sightingReversed });
  }

  handleOpenCreateNested() {
    this.setState({ openCreatedNested: true });
  }

  handleCloseCreateNested() {
    this.setState({ openCreatedNested: false });
  }

  handleReverseNested() {
    this.setState({ nestedReversed: !this.state.nestedReversed });
  }

  handleOpenEditItem() {
    if (
      this.props.numberOfSelectedNodes === 1
      && !this.props.selectedNodes[0].parent_types.includes(
        'basic-relationship',
      )
      && !this.props.selectedNodes[0].parent_types.includes(
        'Stix-Cyber-Observable',
      )
    ) {
      this.setState({ openEditDomainObject: true });
    } else if (
      this.props.numberOfSelectedNodes === 1
      && this.props.selectedNodes[0].parent_types.includes('Stix-Cyber-Observable')
    ) {
      this.setState({ openEditObservable: true });
    } else if (
      (this.props.numberOfSelectedLinks === 1
        && this.props.selectedLinks[0].parent_types.includes(
          'stix-core-relationship',
        ))
      || (this.props.numberOfSelectedNodes === 1
        && this.props.selectedNodes[0].parent_types.includes(
          'stix-core-relationship',
        ))
    ) {
      this.setState({ openEditRelation: true });
    } else if (
      (this.props.numberOfSelectedLinks === 1
        && this.props.selectedLinks[0].entity_type
        === 'stix-sighting-relationship')
      || (this.props.numberOfSelectedNodes === 1
        && this.props.selectedNodes[0].entity_type
        === 'stix-sighting-relationship')
    ) {
      this.setState({ openEditSighting: true });
    } else if (
      (this.props.numberOfSelectedLinks === 1
        && this.props.selectedLinks[0].parent_types.some((el) => isStixNestedRefRelationship(el)))
      || (this.props.numberOfSelectedNodes === 1
        && this.props.selectedNodes[0].parent_types.some((el) => isStixNestedRefRelationship(el)))
    ) {
      this.setState({ openEditNested: true });
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
    this.props.handleCloseRelationEdition(
      this.props.selectedLinks[0]?.id ?? null,
    );
  }

  handleCloseNestedEdition() {
    this.setState({ openEditNested: false });
    this.props.handleCloseRelationEdition(
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
      handleResetLayout,
      displayTimeRange,
      timeRangeInterval,
      selectedTimeRangeInterval,
      handleToggleDisplayTimeRange,
      handleTimeRangeChange,
      timeRangeValues,
      theme,
      navOpen,
      resetAllFilters,
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
      openCreatedRelation,
      openCreatedSighting,
      openCreatedNested,
      relationReversed,
      sightingReversed,
      nestedReversed,
      openEditRelation,
      openEditSighting,
      openEditDomainObject,
      openEditObservable,
      openEditNested,
      deleteObject,
    } = this.state;
    const isInferred = selectedNodes.filter((n) => n.inferred || n.isNestedInferred).length
      > 0
      || selectedLinks.filter((n) => n.inferred || n.isNestedInferred).length > 0;
    const editionEnabled = (!isInferred
        && numberOfSelectedNodes === 1
        && numberOfSelectedLinks === 0
        && selectedNodes.length === 1)
      || (!isInferred
        && numberOfSelectedNodes === 0
        && numberOfSelectedLinks === 1
        && selectedLinks.length === 1
        && !(
          selectedLinks[0].parent_types.includes('stix-ref-relationship')
          && !selectedLinks[0].datable
        ));
    const deletionEnabled = !isInferred
      && (numberOfSelectedNodes !== 0 || numberOfSelectedLinks !== 0);
    const fromSelectedTypes = numberOfSelectedNodes >= 2 && selectedNodes.length >= 2
      ? R.uniq(R.map((n) => n.entity_type, R.init(selectedNodes)))
      : [];
    const toSelectedTypes = numberOfSelectedNodes >= 2 && selectedNodes.length >= 2
      ? R.uniq(R.map((n) => n.entity_type, R.tail(selectedNodes)))
      : [];
    const relationEnabled = (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1);
    const sightingEnabled = (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1);
    const nestedEnabled = (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0)
      || (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1);
    let relationFromObjects = null;
    let relationToObjects = null;
    if (fromSelectedTypes.length === 1 && numberOfSelectedLinks === 0) {
      relationFromObjects = relationReversed || sightingReversed || nestedReversed
        ? [R.last(selectedNodes)]
        : R.init(selectedNodes);
      relationToObjects = relationReversed || sightingReversed || nestedReversed
        ? R.init(selectedNodes)
        : [R.last(selectedNodes)];
    } else if (toSelectedTypes.length === 1 && numberOfSelectedLinks === 0) {
      relationFromObjects = relationReversed || sightingReversed || nestedReversed
        ? R.tail(selectedNodes)
        : [R.head(selectedNodes)];
      relationToObjects = relationReversed || sightingReversed || nestedReversed
        ? [R.head(selectedNodes)]
        : R.tail(selectedNodes);
    } else if (numberOfSelectedNodes === 1 && numberOfSelectedLinks === 1) {
      relationFromObjects = relationReversed || sightingReversed || nestedReversed
        ? [selectedNodes[0]]
        : [selectedLinks[0]];
      relationToObjects = relationReversed || sightingReversed || nestedReversed
        ? [selectedLinks[0]]
        : [selectedNodes[0]];
    }
    const stixCoreObjectOrRelationshipId = (selectedNodes[0]?.id ?? null) || (selectedLinks[0]?.id ?? null);
    return (
        <UserContext.Consumer>
          {({ bannerSettings }) => (
            <Drawer anchor="bottom" variant="permanent"
              classes={{ paper: classes.bottomNav }}
              PaperProps={{
                variant: 'elevation',
                elevation: 1,
                style: { bottom: bannerSettings.bannerHeightNumber },
              }}
            >
              <div style={{
                height: displayTimeRange ? 134 : 54,
                verticalAlign: 'top',
                transition: 'height 0.2s linear',
              }}>
                <div style={{
                  verticalAlign: 'top',
                  width: '100%',
                  height: 54,
                  paddingTop: 3,
                }}>
                  <div
                    style={{
                      float: 'left',
                      marginLeft: navOpen ? 185 : 60,
                      height: '100%',
                      display: 'flex',
                    }}
                  >
                    <Tooltip
                      title={t('Enable 3D mode')}
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
                  </div>
                  {report && (
                    <div style={{ float: 'right', display: 'flex', height: '100%' }}>
                        <ContainerAddStixCoreObjects
                          containerId={report.id}
                          containerStixCoreObjects={report.objects.edges}
                          knowledgeGraph={true}
                          defaultCreatedBy={report.createdBy ?? null}
                          defaultMarkingDefinitions={(
                            report.objectMarking?.edges ?? []
                          ).map((n) => n.node)}
                          targetStixCoreObjectTypes={[
                            'Stix-Domain-Object',
                            'Stix-Cyber-Observable',
                          ]}
                          onAdd={onAdd}
                          onDelete={onDelete}
                          confidence={report.confidence}
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
                        handleClose={this.handleCloseDomainObjectEdition.bind(this)}
                        noStoreUpdate={true}
                      />
                      <StixCyberObservableEdition
                        open={openEditObservable}
                        stixCyberObservableId={selectedNodes[0]?.id ?? null}
                        handleClose={this.handleCloseObservableEdition.bind(this)}
                      />
                      {stixCoreObjectOrRelationshipId != null && (
                        <>
                          <StixCoreRelationshipEdition
                            open={openEditRelation}
                            stixCoreRelationshipId={stixCoreObjectOrRelationshipId}
                            handleClose={this.handleCloseRelationEdition.bind(this)}
                            noStoreUpdate={true}
                          />
                          <StixSightingRelationshipEdition
                            open={openEditSighting}
                            stixSightingRelationshipId={
                              stixCoreObjectOrRelationshipId
                            }
                            handleClose={this.handleCloseSightingEdition.bind(this)}
                            noStoreUpdate={true}
                          />
                          <StixNestedRefRelationshipEdition
                            open={openEditNested}
                            stixNestedRefRelationshipId={
                              stixCoreObjectOrRelationshipId
                            }
                            handleClose={this.handleCloseNestedEdition.bind(this)}
                            noStoreUpdate={true}
                          />
                        </>
                      )}
                      {onAddRelation && (
                        <Tooltip title={t('Create a relationship')}>
                          <span>
                            <IconButton
                              color="primary"
                              onClick={this.handleOpenCreateRelationship.bind(this)}
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
                          startTime={
                            lastLinkFirstSeen || dateFormat(report.published)
                          }
                          stopTime={lastLinkLastSeen || dateFormat(report.published)}
                          confidence={report.confidence}
                          handleClose={this.handleCloseCreateRelationship.bind(this)}
                          handleResult={onAddRelation}
                          handleReverseRelation={this.handleReverseRelation.bind(
                            this,
                          )}
                          defaultCreatedBy={convertCreatedBy(report)}
                          defaultMarkingDefinitions={convertMarkings(report)}
                        />
                      )}
                      {onAddRelation && (
                        <Tooltip title={t('Create a nested relationship')}>
                          <span>
                            <IconButton
                              color="primary"
                              onClick={this.handleOpenCreateNested.bind(this)}
                              disabled={!nestedEnabled}
                              size="large"
                            >
                              <ReadMoreOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      {onAddRelation && (
                        <StixNestedRefRelationshipCreation
                          open={openCreatedNested}
                          fromObjects={relationFromObjects}
                          toObjects={relationToObjects}
                          startTime={
                            lastLinkFirstSeen || dateFormat(report.published)
                          }
                          stopTime={lastLinkLastSeen || dateFormat(report.published)}
                          confidence={report.confidence}
                          handleClose={this.handleCloseCreateNested.bind(this)}
                          handleResult={onAddRelation}
                          handleReverseRelation={this.handleReverseNested.bind(this)}
                          defaultMarkingDefinitions={(
                            report.objectMarking?.edges ?? []
                          ).map((n) => n.node)}
                        />
                      )}
                      {onAddRelation && (
                        <Tooltip title={t('Create a sighting')}>
                          <span>
                            <IconButton
                              color="primary"
                              onClick={this.handleOpenCreateSighting.bind(this)}
                              disabled={!sightingEnabled}
                              size="large"
                            >
                              <VisibilityOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      {onAddRelation && (
                        <StixSightingRelationshipCreation
                          open={openCreatedSighting}
                          fromObjects={relationFromObjects}
                          toObjects={relationToObjects}
                          firstSeen={
                            lastLinkFirstSeen || dateFormat(report.published)
                          }
                          lastSeen={lastLinkLastSeen || dateFormat(report.published)}
                          confidence={report.confidence}
                          handleClose={this.handleCloseCreateSighting.bind(this)}
                          handleResult={onAddRelation}
                          handleReverseSighting={this.handleReverseSighting.bind(
                            this,
                          )}
                          defaultCreatedBy={convertCreatedBy(report)}
                          defaultMarkingDefinitions={convertMarkings(report)}
                        />
                      )}
                      {handleDeleteSelected && (
                        <Tooltip title={t('Remove selected items')}>
                          <span>
                            <IconButton
                              color="primary"
                              onClick={this.handleOpenRemove.bind(this)}
                              disabled={!deletionEnabled}
                              size="large"
                            >
                              <DeleteOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      <Dialog
                        open={this.state.displayRemove}
                        keepMounted={true}
                        PaperProps={{ elevation: 1 }}
                        TransitionComponent={Transition}
                        onClose={this.handleCloseRemove.bind(this)}
                      >
                        <DialogContent>
                          <Typography variant="body">
                            {t(
                              'Do you want to remove these elements from this report?',
                            )}
                          </Typography>
                          <Alert
                            severity="warning"
                            variant="outlined"
                            style={{ marginTop: 20 }}
                          >
                            <AlertTitle>{t('Cascade delete')}</AlertTitle>
                            <FormGroup>
                              <FormControlLabel
                                control={
                                  <Checkbox
                                    checked={deleteObject}
                                    onChange={this.handleToggleDeleteObject.bind(
                                      this,
                                    )}
                                  />
                                }
                                label={t(
                                  'Delete the element if no other containers contain it',
                                )}
                              />
                            </FormGroup>
                          </Alert>
                        </DialogContent>
                        <DialogActions>
                          <Button onClick={this.handleCloseRemove.bind(this)}>
                            {t('Cancel')}
                          </Button>
                          <Button
                            onClick={() => {
                              this.handleCloseRemove();
                              handleDeleteSelected(deleteObject);
                            }}
                            color="secondary"
                          >
                            {t('Remove')}
                          </Button>
                        </DialogActions>
                      </Dialog>
                    </div>
                  )}
                  <div className="clearfix" />
                  <div
                    style={{
                      height: '100%',
                      padding: navOpen ? '30px 10px 0px 190px' : '30px 10px 0px 65px',
                    }}
                  >
                    <div
                      style={{
                        position: 'absolute',
                        width: '100%',
                        height: '100%',
                        bottom: -50,
                        left: 120,
                      }}
                    >
                      <ResponsiveContainer width="100%" height={60}>
                        <ScatterChart
                          width="100%"
                          height={60}
                          margin={{
                            top: 32,
                            right: 150,
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
              </div>
            </Drawer>
          )}
        </UserContext.Consumer>
    );
  }
}

ReportKnowledgeGraphBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  report: PropTypes.object,
  handleToggle3DMode: PropTypes.func,
  handleToggleRectangleSelectModeFree: PropTypes.func,
  handleToggleSelectModeFree: PropTypes.func,
  currentMode3D: PropTypes.bool,
  handleToggleTreeMode: PropTypes.func,
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
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
  onAddRelation: PropTypes.func,
  handleDeleteSelected: PropTypes.func,
  lastLinkFirstSeen: PropTypes.string,
  lastLinkLastSeen: PropTypes.string,
  handleCloseEntityEdition: PropTypes.func,
  handleCloseRelationEdition: PropTypes.func,
  handleSelectAll: PropTypes.func,
  handleSelectByType: PropTypes.func,
  handleResetLayout: PropTypes.func,
  displayTimeRange: PropTypes.bool,
  handleToggleDisplayTimeRange: PropTypes.func,
  handleTimeRangeChange: PropTypes.func,
  timeRangeInterval: PropTypes.array,
  selectedTimeRangeInterval: PropTypes.array,
  timeRangeValues: PropTypes.array,
  theme: PropTypes.object,
  navOpen: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(ReportKnowledgeGraphBar);
