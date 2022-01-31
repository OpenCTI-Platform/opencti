/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import inject18n from '../../../components/i18n';
import ToolBar from '../data/ToolBar';
import { isUniqFilter } from '../common/lists/Filters';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import NewAnalysis from './modals/NewAnalysis';
import Delete from './modals/Delete';
import ExportCSV from './modals/ExportCSV';
import GenerateReport from './modals/GenerateReport';
import VulnerabilityScan from './modals/VulnerabilityScan';
import DescriptionIcon from '@material-ui/icons/Description';
import AddIcon from '@material-ui/icons/Add';
import EditOutlinedIcon from '@material-ui/icons/EditOutlined';
import ExploreIcon from '@material-ui/icons/Explore';
import ShowChartIcon from '@material-ui/icons/ShowChart';
import DeleteIcon from '@material-ui/icons/Delete';
import IconButton from '@material-ui/core/IconButton';
import CloudUploadIcon from '@material-ui/icons/CloudUpload';
import ArrowDropDownIcon from '@material-ui/icons/ArrowDropDown';
import ImportExportIcon from '@material-ui/icons/ImportExport';
import CompareIcon from '@material-ui/icons/Compare';
import ScannerIcon from '@material-ui/icons/Scanner';
import PublishIcon from '@material-ui/icons/Publish';
import Button from '@material-ui/core/Button';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardActions from '@material-ui/core/CardActions';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Typography from '@material-ui/core/Typography';
import CardContent from '@material-ui/core/CardContent';
import { DescriptionOutlined } from '@material-ui/icons';
import { makeStyles } from '@material-ui/core/styles';
import { fetchAllScans } from '../../../services/scan.service';
import { fetchAllAnalysis } from '../../../services/analysis.service';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import moment from 'moment';
import Dialog from '@material-ui/core/Dialog';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Box from '@material-ui/core/Box';
import Checkbox from '@material-ui/core/Checkbox';
import {
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
  ScatterChart,
  Scatter,
  LineChart, 
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
  ReferenceLine,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import Chip from '@material-ui/core/Chip';
import {
  getCVESeverityChartData,
  getSeverityPieChartData,
  getTopVulnerableHostsChartData,
  getTopVulnerableProductsChartData,
  getTrendingChartData,
} from '../../../services/api.service';

function TabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box p={3}>
          <Typography>{children}</Typography>
        </Box>
      )}
    </div>
  );
}

TabPanel.propTypes = {
  children: PropTypes.node,
  index: PropTypes.any.isRequired,
  value: PropTypes.any.isRequired,
};

function a11yProps(index) {
  return {
    id: `simple-tab-${index}`,
    'aria-controls': `simple-tabpanel-${index}`,
  };
}

class ViewCharts extends Component {
  constructor(props) {
    super(props);

    this.state = {
      tabValue: 0,
      anchorEl: false,
      clientId: localStorage.getItem('client_id'),
      analysis_id: this.props.location.state.analysis_id,
      analysises: this.props.location.state.analysises,
      analysisesIDs: this.getAnalysisesID(this.props.location.state.analysises),
      severityChartData: null,
      vulnerabilityByYearChartData: null,
      topVulnerableHost: null,
      topVulnerableProducts: null,
      trendingChatData: null,
      isDisabled: true,
      checked: [],
    };
  }

  getAnalysisesID = (analysises) => {
    const analysisesIDs = [];

    analysises.map((analysis) => {
      analysisesIDs.push(analysis.id);
    });

    return analysisesIDs;
  };

  componentDidMount() {
    this.setState({isDisabled: true});

    getSeverityPieChartData(this.state.clientId,  this.props.location.state.analysis_id)
      .then((response) => {
        this.setState({ severityChartData: response.data });
        this.state.checked.push(this.props.location.state.index);
        this.setState({isDisabled: false});
      })
      .catch((error) => {
        console.log(error);
      });
  }

  render() {
    const {
      tabValue,
      anchorEl,
      analysises,
      analysisesIDs,
      severityChartData,
      vulnerabilityByYearChartData,
      topVulnerableHost,
      topVulnerableProducts,
      trendingChatData,
      checked,
      isDisabled,
    } = this.state;

    const COLORS = {
      Low: '#FCCF7E',
      Medium: '#F9B406',
      High: '#E28120',
      Severe: '#A33611',
      Critical: '#7F0909',
    };

    const handleTabChange = (event, newValue) => {
      this.setState({ tabValue: newValue });

      const ids = this.state.analysisesIDs.map((i) => i).join();

      switch (newValue) {
        case 1:
          this.setState({isDisabled: false});
          if (vulnerabilityByYearChartData == null) {
            getCVESeverityChartData(this.state.clientId, ids)
              .then((response) => {
                this.setState({ vulnerabilityByYearChartData: response.data });
              })
              .catch((error) => {
                console.log(error);
              });
          }

          break;
        case 2:
          this.setState({isDisabled: false});
          if (topVulnerableHost == null) {
            getTopVulnerableHostsChartData(this.state.clientId, ids)
              .then((response) => {
                this.setState({ topVulnerableHost: response.data });
              })
              .catch((error) => {
                console.log(error);
              });
          }

          break;
        case 3:
          this.setState({isDisabled: false});
          if (topVulnerableProducts == null) {
            getTopVulnerableProductsChartData(this.state.clientId, ids)
              .then((response) => {
                this.setState({ topVulnerableProducts: response.data });
              })
              .catch((error) => {
                console.log(error);
              });
          }
          break;
        case 4:
          this.setState({isDisabled: true});
          if (trendingChatData == null) {
            getTrendingChartData(this.state.clientId, ids)
              .then((response) => {
                const trendingData = response.data.map((item) => {
                  return {
                    name: item.id,
                    data: item.data.map((item) => {
                      return {
                        category: item.x,
                        value: parseInt(item.y),
                      };
                    }),
                  };
                });
                this.setState({ trendingChatData: trendingData });
              })
              .catch((error) => {
                console.log(error);
              });
          }

          break;
      }
    };

    const handleClick = () => {
      this.setState({ anchorEl: true });
    };

    const handleClose = () => {
      this.setState({ anchorEl: null });
    };

    const handleToggle = (value, id) => () => {

      const currentIndex = checked.indexOf(value);
      const analysis_id = id;

      if (currentIndex === -1) {
                
        switch (tabValue) {
          case 0:
            this.setState({isDisabled: false});
            getSeverityPieChartData(this.state.clientId, analysis_id)
              .then((response) => {
                const data = response.data;
                this.setState({ severityChartData: [ ...this.state.severityChartData, ...data ] })
                this.setState({ isDisabled: false });
              })
              .catch((error) => {
                console.log(error);
              });

          break;
          case 1:
            this.setState({isDisabled: false});
            if (vulnerabilityByYearChartData == null) {
              getCVESeverityChartData(this.state.clientId, ids)
                .then((response) => {
                  this.setState({ vulnerabilityByYearChartData: response.data });
                })
                .catch((error) => {
                  console.log(error);
                });
            }

            break;
          case 2:
            this.setState({isDisabled: false});
            if (topVulnerableHost == null) {
              getTopVulnerableHostsChartData(this.state.clientId, ids)
                .then((response) => {
                  this.setState({ topVulnerableHost: response.data });
                })
                .catch((error) => {
                  console.log(error);
                });
            }

            break;
          case 3:
            this.setState({isDisabled: false});
            if (topVulnerableProducts == null) {
              getTopVulnerableProductsChartData(this.state.clientId, ids)
                .then((response) => {
                  this.setState({ topVulnerableProducts: response.data });
                })
                .catch((error) => {
                  console.log(error);
                });
            }
            break;
          case 4:
            this.setState({isDisabled: true});
            if (trendingChatData == null) {
              getTrendingChartData(this.state.clientId, ids)
                .then((response) => {
                  const trendingData = response.data.map((item) => {
                    return {
                      name: item.id,
                      data: item.data.map((item) => {
                        return {
                          category: item.x,
                          value: parseInt(item.y),
                        };
                      }),
                    };
                  });
                  this.setState({ trendingChatData: trendingData });
                })
                .catch((error) => {
                  console.log(error);
                });
            }

          break;
      }


        checked.push(value);


      } else {
        checked.splice(currentIndex, 1);
      }
    };

    return (
      <div>
        <Button
          aria-controls="simple-menu"
          aria-haspopup="true"
          variant="contained"
          color="primary"
          onClick={handleClick}
          disabled={isDisabled}
        >
          Select Analyses [ {checked.length} ]
        </Button>
        <Menu
          id="simple-menu"
          anchorEl={anchorEl}
          keepMounted
          open={Boolean(anchorEl)}
          onClose={handleClose}
        >
          <List>
            {analysises &&
              analysises.map((analysis, i) => {
                return (
                  <MenuItem onClick={handleClose}>
                    <ListItem key={i}>
                      <ListItemText
                        id={analysis.id}
                        primary={analysis.scan.scan_name}
                        secondary={
                          <React.Fragment>
                            <div style={{ marginBottom: 10 }}>
                              {moment(analysis.completed_date).fromNow()}
                            </div>
                            {analysis.weakness_range && (
                              <Chip
                                size="small"
                                style={{ margin: 3 }}
                                label={`Top  ${analysis.weakness_range}`}
                              />
                            )}
                            {analysis.vulnerability_range && (
                              <Chip
                                size="small"
                                style={{ margin: 3 }}
                                label={`Previous ${analysis.vulnerability_range} Years`}
                              />
                            )}
                            {analysis.vignette_name && (
                              <Chip
                                size="small"
                                style={{ margin: 3 }}
                                label={analysis.vignette_name}
                              />
                            )}
                          </React.Fragment>
                        }
                      />
                      <ListItemSecondaryAction>
                        <Checkbox
                          edge="end"
                          onChange={handleToggle(i, analysis.id)}
                          checked={checked.indexOf(i) !== -1}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  </MenuItem>
                );
              })}
          </List>
        </Menu>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label="Severity" {...a11yProps(0)} />
          <Tab label="Vulnerabilities by Year" />
          <Tab label="Top Vulnerable Hosts" />
          <Tab label="Top Vulnerable Products" />
          <Tab label="Trending" />
        </Tabs>
        <Grid container={true} spacing={3}>
          <TabPanel
            style={{ minHeight: 700, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={0}
          >
            { severityChartData &&

              checked.sort().map((i) => {
               
                  const array = severityChartData[i]?.data?.map((item) => {
                    return {
                      name: item.label,
                      value: parseInt(item.value),
                    };
                  });

               
              return (
                <Grid item={true}>
                  <Typography variant="h4" gutterBottom={true}>
                    {analysises[i].scan.scan_name} :{' '}
                    {moment(analysises[i].completed_date).fromNow()}
                  </Typography>
                  <Paper
                    elevation={2}
                    style={{
                      height: 500,
                      width: '100%',
                      marginBottom: 40,
                      padding: 10,
                    }}
                  >
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart width={600} height={600}>
                      {array &&
                        <Pie
                          data={array}
                          nameKey="name"
                          dataKey="value"
                          cx={500}
                          cy={200}
                          innerRadius={40}
                          outerRadius={80}
                          fill="#82ca9d"
                          label={({
                            cx,
                            cy,
                            midAngle,
                            innerRadius,
                            outerRadius,
                            value,
                            index,
                          }) => {
                            const RADIAN = Math.PI / 180;
                            // eslint-disable-next-line
                            const radius =
                              25 + innerRadius + (outerRadius - innerRadius);
                            // eslint-disable-next-line
                            const x =
                              cx + radius * Math.cos(-midAngle * RADIAN);
                            // eslint-disable-next-line
                            const y =
                              cy + radius * Math.sin(-midAngle * RADIAN);

                            return (
                              <text
                                x={x}
                                y={y}
                                fill={COLORS[array[index].name]}
                                textAnchor={x > cx ? 'start' : 'end'}
                                dominantBaseline="central"
                              >
                                {array[index].name} ({value})
                              </text>
                            );
                          }}
                        >
                          {array.map((entry, index) => (
                            <Cell
                              key={`cell-${index}`}
                              fill={COLORS[entry.name]}
                            />
                          ))}
                          <Tooltip />
                        </Pie>
                      }
                      </PieChart>
                    </ResponsiveContainer>
                  </Paper>
                </Grid>
              );
            })}
          </TabPanel>
          <TabPanel
            style={{ minHeight: 700, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={1}
          >
            {vulnerabilityByYearChartData &&
              checked.sort().map((i) => {
                return (
                  <Grid item={true}>
                    <Typography variant="h4" gutterBottom={true}>
                      {analysises[i].scan.scan_name} :{' '}
                      {moment(analysises[i].completed_date).fromNow()}
                    </Typography>
                    <Paper
                      elevation={2}
                      style={{
                        height: 500,
                        width: '100%',
                        marginBottom: 40,
                        padding: 10,
                      }}
                    >
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          width={500}
                          height={300}
                          data={vulnerabilityByYearChartData[i].data}
                          margin={{
                            top: 20,
                            right: 30,
                            left: 20,
                            bottom: 5,
                          }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis
                            dataKey="year"
                            type="number"
                            domain={[1999, 2021]}
                          />
                          <YAxis type="number" />
                          <Tooltip cursor={false}/>
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FCCF7E"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FCCF7E" />
                          <Bar stackId="a" dataKey="Medium" fill="#F9B406" />
                          <Bar stackId="a" dataKey="High" fill="#E28120" />
                          <Bar stackId="a" dataKey="Severe" fill="#A33611" />
                          <Bar stackId="a" dataKey="Critical" fill="#7F0909" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Paper>
                  </Grid>
                );
              })}
          </TabPanel>
          <TabPanel
            style={{ minHeight: 700, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={2}
          >
            {topVulnerableHost &&
              checked.sort().map((i) => {
                return (
                  <Grid item={true}>
                    <Typography variant="h4" gutterBottom={true}>
                      {analysises[i].scan.scan_name} :{' '}
                      {moment(analysises[i].completed_date).fromNow()}
                    </Typography>
                    <Paper
                      elevation={2}
                      style={{
                        height: 500,
                        width: '100%',
                        marginBottom: 40,
                        padding: 10,
                      }}
                    >
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          layout="vertical"
                          width={500}
                          height={300}
                          data={topVulnerableHost[i].data}
                          margin={{
                            top: 20,
                            right: 30,
                            left: 20,
                            bottom: 5,
                          }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" domain={[0, 'auto']} />
                          <YAxis type="category" dataKey="host" />
                          <Tooltip cursor={false}/>
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FCCF7E"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FCCF7E" />
                          <Bar stackId="a" dataKey="Medium" fill="#F9B406" />
                          <Bar stackId="a" dataKey="High" fill="#E28120" />
                          <Bar stackId="a" dataKey="Severe" fill="#A33611" />
                          <Bar stackId="a" dataKey="Critical" fill="#7F0909" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Paper>
                  </Grid>
                );
              })}
          </TabPanel>
          <TabPanel
            style={{ minHeight: 700, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={3}
          >
            {topVulnerableProducts &&
              checked.sort().map((i) => {
                return (
                  <Grid item={true}>
                    <Typography variant="h4" gutterBottom={true}>
                      {analysises[i].scan.scan_name} :{' '}
                      {moment(analysises[i].completed_date).fromNow()}
                    </Typography>
                    <Paper
                      elevation={2}
                      style={{ height: 500, width: '100%', marginBottom: 40 }}
                    >
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          layout="vertical"
                          width={500}
                          height={300}
                          data={topVulnerableProducts[i].data}
                          margin={{
                            top: 20,
                            right: 30,
                            left: 20,
                            bottom: 5,
                          }}
                        >
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" domain={[0, 'auto']} />
                          <YAxis type="category" dataKey="product" />
                          <Tooltip cursor={false}/>
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FCCF7E"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FCCF7E" />
                          <Bar stackId="a" dataKey="Medium" fill="#F9B406" />
                          <Bar stackId="a" dataKey="High" fill="#E28120" />
                          <Bar stackId="a" dataKey="Severe" fill="#A33611" />
                          <Bar stackId="a" dataKey="Critical" fill="#7F0909" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Paper>
                  </Grid>
                );
              })}
          </TabPanel>
          <TabPanel
            style={{ minHeight: 700, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={4}
          >
            <Grid item={true}>
              <Paper
                elevation={2}
                style={{
                  height: 500,
                  width: '100%',
                  marginBottom: 40,
                }}
              >
               {trendingChatData &&
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart width={500} height={300}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      dataKey="category"
                      type="category"
                      allowDuplicatedCategory={false}
                      tick={{ fill: 'white' }}
                    />
                    <YAxis dataKey="value" tick={{ fill: 'white' }}/>
                    <Tooltip />
                    <Legend wrapperStyle={{ bottom: 0 }} />
                    {trendingChatData.map((s) => (
                      <Line
                        dataKey="value"
                        data={s.data}
                        name={s.name}
                        key={s.name}
                        dot={{ r: 8 }}
                        activeDot={{ r: 8 }}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              }
              </Paper>
            </Grid>
          </TabPanel>
        </Grid>
      </div>
    );
  }
}

export default R.compose(inject18n, withRouter)(ViewCharts);
