import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import { AspectRatio, FilterListOutlined, AccountBalanceOutlined, CenterFocusStrongOutlined, ScatterPlotOutlined, DateRangeOutlined } from '@mui/icons-material';
import { Video3d, SelectAll, SelectGroup, AutoFix, FamilyTree } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import Popover from '@mui/material/Popover';
import Divider from '@mui/material/Divider';
import TimeRange from 'react-timeline-range-slider';
import { ResponsiveContainer, Scatter, ScatterChart, YAxis, ZAxis } from 'recharts';
import Slide from '@mui/material/Slide';
import inject18n from '../../../../components/i18n';
import { dateFormat } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import { resolveLink } from '../../../../utils/Entity';
import { parseDomain } from '../../../../utils/Graph';
import { UserContext } from '../../../../utils/hooks/useAuth';

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

class StixCoreObjectOrStixCoreRelationshipContainersGraphBar extends Component {
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
      relationReversed: false,
      openEditRelation: false,
      openEditEntity: false,
      displayRemove: false,
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
      handleToggle3DMode,
      handleToggleTreeMode,
      handleToggleFixedMode,
      handleToggleCreatedBy,
      handleToggleMarkedBy,
      handleToggleStixCoreObjectType,
      handleZoomToFit,
      stixCoreObjectsTypes,
      createdBy,
      markedBy,
      report,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      selectedNodes,
      selectedLinks,
      handleSelectAll,
      handleResetLayout,
      displayTimeRange,
      timeRangeInterval,
      selectedTimeRangeInterval,
      handleToggleDisplayTimeRange,
      handleTimeRangeChange,
      timeRangeValues,
      disabled,
      theme,
      navOpen,
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
    } = this.state;
    if (disabled) {
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
                style: { bottom: bannerSettings.bannerHeightNumber },
              }}
            >
              <div
                style={{
                  height: displayTimeRange ? 134 : 54,
                  verticalAlign: 'top',
                  transition: 'height 0.2s linear',
                }}
              >
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
                        currentMode3D
                          ? t('Disable 3D mode')
                          : t('Enable 3D mode')
                      }
                    >
                      <span>
                        <IconButton
                          color={currentMode3D ? 'secondary' : 'primary'}
                          disabled={true}
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
                          disabled={true}
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
                          disabled={true}
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
                          disabled={true}
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
                          disabled={true}
                          size="large"
                        >
                          <AspectRatio />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={t('Unfix the nodes and re-apply forces')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <AutoFix />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Divider
                      className={classes.divider}
                      orientation="vertical"
                    />
                    <Tooltip title={t('Filter entity types')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <FilterListOutlined />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={t('Display time range selector')}>
                      <span>
                        <IconButton
                          color={displayTimeRange ? 'secondary' : 'primary'}
                          disabled={true}
                          size="large"
                        >
                          <DateRangeOutlined />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={t('Filter marking definitions')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <CenterFocusStrongOutlined />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={t('Filter authors (created by)')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <AccountBalanceOutlined />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Divider
                      className={classes.divider}
                      orientation="vertical"
                    />
                    <Tooltip title={t('Select by entity type')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <SelectGroup />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title={t('Select all nodes')}>
                      <span>
                        <IconButton
                          color="primary"
                          disabled={true}
                          size="large"
                        >
                          <SelectAll />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </div>
                  {report && (
                    <div
                      style={{
                        float: 'right',
                        display: 'flex',
                        height: '100%',
                      }}
                    ></div>
                  )}
                  <div className="clearfix" />
                </div>
              </div>
            </Drawer>
          )}
        </UserContext.Consumer>
      );
    }
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
              style: { bottom: bannerSettings.bannerHeightNumber },
            }}
          >
            <div
              style={{
                height: displayTimeRange ? 134 : 54,
                verticalAlign: 'top',
                transition: 'height 0.2s linear',
              }}
            >
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
                  <Tooltip title={t('Fit graph to canvas')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={handleZoomToFit.bind(this)}
                        size="large"
                      >
                        <AspectRatio />
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
                  <Tooltip title={t('Filter entity types')}>
                    <span>
                      <IconButton
                        color="primary"
                        onClick={this.handleOpenStixCoreObjectsTypes.bind(this)}
                        size="large"
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
                              checked={
                                !currentMarkedBy.includes(markingDefinition.id)
                              }
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
                        size="large"
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
                  <Divider className={classes.divider} orientation="vertical" />
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
                </div>
                <div
                  style={{
                    float: 'right',
                    display: 'flex',
                    height: '100%',
                  }}
                >
                  <Tooltip title={t('View the item')}>
                    <span>
                      <IconButton
                        color="primary"
                        component={Link}
                        target="_blank"
                        to={viewLink}
                        disabled={!viewEnabled}
                        size="large"
                      ></IconButton>
                    </span>
                  </Tooltip>
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
            </div>
          </Drawer>
        )}
      </UserContext.Consumer>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipContainersGraphBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  report: PropTypes.object,
  handleToggle3DMode: PropTypes.func,
  currentMode3D: PropTypes.bool,
  handleToggleTreeMode: PropTypes.func,
  currentModeTree: PropTypes.string,
  currentModeFixed: PropTypes.bool,
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
  view: PropTypes.string,
  handleChangeView: PropTypes.func,
  numberOfSelectedNodes: PropTypes.number,
  numberOfSelectedLinks: PropTypes.number,
  handleSelectAll: PropTypes.func,
  handleSelectByType: PropTypes.func,
  handleResetLayout: PropTypes.func,
  displayTimeRange: PropTypes.bool,
  handleToggleDisplayTimeRange: PropTypes.func,
  handleTimeRangeChange: PropTypes.func,
  timeRangeInterval: PropTypes.array,
  selectedTimeRangeInterval: PropTypes.array,
  timeRangeValues: PropTypes.array,
  disabled: PropTypes.bool,
  theme: PropTypes.object,
  navOpen: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipContainersGraphBar);
