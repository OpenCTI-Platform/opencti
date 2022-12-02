/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Redirect } from 'react-router-dom';
import * as R from 'ramda';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Typography from '@material-ui/core/Typography';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import moment from 'moment';
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
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../components/i18n';
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
    const analysesMap = {}
    this.props.location.state?.analyses.forEach((a) => analysesMap[a.id] = a);
    this.state = {
      trendingData: [],
      trendingName: '',
      tabValue: 0,
      anchorEl: false,
      clientId: localStorage.getItem('client_id'),
      analysis_id: (this.props.location.state ? this.props.location.state.analysis_id : null),
      analysises: analysesMap,
      severityChartData: {},
      vulnerabilityByYearChartData: {},
      topVulnerableHost: {},
      topVulnerableProducts: {},
      trendingChatData: [],
      isDisabled: true,
      checked: {},
    };
  }

  getAnalysisesID = (analysises) => {
    const analysisesIDs = [];

    analysises.forEach((analysis) => {
      checked[analysis.id] = false;
    });

    return analysisesIDs;
  };

  componentDidMount() {
    this.setState({ isDisabled: true });

    getSeverityPieChartData(this.state.clientId, this.state.analysis_id)
      .then((response) => {
        const analysisId = this.state.analysis_id;
        const severityChartData = {};
        severityChartData[analysisId] = response.data[0];
        this.setState({ severityChartData });
        const checked = this.state.checked;
        checked[analysisId] = true;
        this.setState({ checked })
        this.setState({ isDisabled: false });
      })
      .catch((error) => {
        console.log(error);
      });
  }

  handleTrendingClick(s) {
    const { value } = s;
    const { trendingData } = this.state;
    if (trendingData.includes(value)) {
      this.setState({ trendingData: trendingData.filter((k) => k !== value) })
    } else {
      this.setState({ trendingData: [...trendingData, value] });
    }
  }

  handleMouseEnter(s) {
    const { value } = s;
    this.setState({ trendingName: value });
  }
  handleMouseLeave() {
    this.setState({ trendingName: '' });
  }

  render() {

    if (this.props.location.state == undefined) return <Redirect to="/activities/vulnerability_assessment/scans" />;

    const {
      tabValue,
      anchorEl,
      analysises,
      severityChartData,
      vulnerabilityByYearChartData,
      topVulnerableHost,
      topVulnerableProducts,
      trendingChatData,
      checked,
      isDisabled,
    } = this.state;

    const COLORS = {
      Low: '#FFD773',
      Medium: '#FFB000',
      High: '#F17B00',
      Severe: '#FF4100',
      Critical: '#FF0000',
      Informational: '#FFEBBC',
    };



    const colorsForTrendingChart = ['#FEECC1', '#3C5A96', '#F9B406', '#2AA3EF', '#F35426', '#11B3A9', '#AD0036', '#16D36D'];

    const handleTabChange = (event, newValue) => {
      this.setState({ tabValue: newValue });
      this.setState({ isDisabled: true });
      const ids = activeChecked().join();
      switch (newValue) {
        case 0:
          getSeverityPieChartData(this.state.clientId, ids)
            .then((response) => {
              response.data.forEach((d) => {
                severityChartData[d.id] = d;
              })
              this.setState({ severityChartData })
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 1:
          getCVESeverityChartData(this.state.clientId, ids)
            .then((response) => {
              response.data.forEach((d) => {
                vulnerabilityByYearChartData[d.id] = d;
              })
              this.setState({ vulnerabilityByYearChartData });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 2:
          this.setState({ isDisabled: false });
          getTopVulnerableHostsChartData(this.state.clientId, ids)
            .then((response) => {
              response.data.forEach((d) => {
                topVulnerableHost[d.id] = d;
              })
              this.setState({ topVulnerableHost });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 3:
          this.setState({ isDisabled: false });
          getTopVulnerableProductsChartData(this.state.clientId, ids)
            .then((response) => {
              response.data.forEach((d) => {
                topVulnerableProducts[d.id] = d;
              })
              this.setState({ topVulnerableProducts });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 4:
          this.setState({ isDisabled: true });
          getTrendingChartData(this.state.clientId, ids)
            .then((response) => {
              const data = response.data.map((item) => {
                return {
                  name: item.id,
                  data: item.data.map((item) => {
                    return {
                      category: item.x,
                      value: parseInt(item.y),
                    };
                  }),
                };
              })
              this.setState({ trendingChatData: data });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });

          break;
      }
    };

    const handleClick = () => {
      this.setState({ anchorEl: true });
    };

    const handleClose = () => {
      this.setState({ anchorEl: null });
    };

    const activeChecked = () => {
      return Object.keys(analysises)
        .filter((id) => checked[id])
    };

    const handleToggle = (isChecked, id) => {
      checked[id] = isChecked
      this.setState({ isDisabled: true });

      if (!isChecked) {
        delete severityChartData[id]
        delete vulnerabilityByYearChartData[id]
        delete topVulnerableHost[id]
        return
      }
      switch (tabValue) {
        case 0:
          getSeverityPieChartData(this.state.clientId, id)
            .then((response) => {
              severityChartData[id] = response.data[0];
              this.setState({ severityChartData })
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 1:
          getCVESeverityChartData(this.state.clientId, id)
            .then((response) => {
              vulnerabilityByYearChartData[id] = response.data[0];
              this.setState({ vulnerabilityByYearChartData });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 2:
          getTopVulnerableHostsChartData(this.state.clientId, id)
            .then((response) => {
              topVulnerableHost[id] = response.data[0];
              this.setState({ topVulnerableHost });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 3:
          getTopVulnerableProductsChartData(this.state.clientId, id)
            .then((response) => {
              topVulnerableProducts[id] = response.data[0];
              this.setState({ topVulnerableProducts });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
        case 4:
          getTrendingChartData(this.state.clientId, activeChecked().join())
            .then((response) => {
              const data = response.data.map((item) => {
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
              this.setState({ trendingChatData: data });
              this.setState({ isDisabled: false });
            })
            .catch((error) => {
              this.setState({ isDisabled: false });
              console.log(error);
            });
          break;
      }
    };

    const CustomTooltip = ({ active, payload, label }) => {
      if (active) {
        return (
          <div
            className='custom-tooltip'
            style={{
              color: 'black',
              backgroundColor: '#ffff',
              padding: '10px',
              border: '1px solid #cccc',
              fontSize: 12,
              fontWeight: 600,
              borderRadius: 10,
            }}
          >
            <label>{`${payload[0].name} (${payload[0].value})`}</label>
          </div>
        );
      }
      return null;
    };
    const { trendingName, trendingData } = this.state;

    return (
      <div style={{ marginTop: '1rem' }}>
        <Button
          aria-controls="simple-menu"
          aria-haspopup="true"
          variant="contained"
          color="primary"
          onClick={handleClick}
          disabled={isDisabled}
        >
          Select Analyses [ {activeChecked().length} ]
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
              Object.entries(analysises).map(([id, analysis]) => {
                return (
                  <MenuItem>
                    <ListItem key={analysis.id}>
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
                          onChange={(e) => {
                            handleToggle(e.target.checked, analysis.id)
                          }}
                          checked={activeChecked().includes(analysis.id)}
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
            {severityChartData && activeChecked().map((i) => {
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
                            cx={500}
                            cy={200}
                            data={array}
                            fill="#82ca9d"
                            nameKey="name"
                            dataKey="value"
                            innerRadius={90}
                            outerRadius={150}
                            labelLine={true}
                            isAnimationActive={false}
                            isUpdateAnimationActive={true}
                            label={({
                              cx,
                              cy,
                              value,
                              index,
                              midAngle,
                              innerRadius,
                              outerRadius,
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
                                  style={{ fontSize: '15px' }}
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
                          </Pie>
                        }
                        <Tooltip content={<CustomTooltip />} />
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
              activeChecked().filter((id) => vulnerabilityByYearChartData[id]).map((i) => {
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
                            tick={{ fill: 'white' }}
                            domain={[1999, 2021]}
                          />
                          <YAxis
                            tick={{ fill: 'white' }}
                            type="number"
                          />
                          <Tooltip cursor={false} />
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FFEBBC"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FFD773" />
                          <Bar stackId="a" dataKey="Medium" fill="#FFB000" />
                          <Bar stackId="a" dataKey="High" fill="#F17B00" />
                          <Bar stackId="a" dataKey="Severe" fill="#FF4100" />
                          <Bar stackId="a" dataKey="Critical" fill="#FF0000" />
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
              activeChecked().filter((id) => topVulnerableHost[id]).map((i) => {
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
                          <XAxis tick={{ fill: 'white' }} type="number" domain={[0, 'auto']} />
                          <YAxis width={210} tick={{ fill: 'white' }} type="category" dataKey="host" />
                          <Tooltip cursor={false} />
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FFEBBC"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FFD773" />
                          <Bar stackId="a" dataKey="Medium" fill="#FFB000" />
                          <Bar stackId="a" dataKey="High" fill="#F17B00" />
                          <Bar stackId="a" dataKey="Severe" fill="#FF4100" />
                          <Bar stackId="a" dataKey="Critical" fill="#FF0000" />
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
              activeChecked().filter((id) => topVulnerableProducts[id]).map((i) => {
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
                          <XAxis tick={{ fill: 'white' }} type="number" domain={[0, 'auto']} />
                          <YAxis tick={{ fill: 'white' }} type="category" dataKey="product" />
                          <Tooltip cursor={false} />
                          <Legend />
                          <Bar
                            stackId="a"
                            dataKey="Informational"
                            fill="#FFEBBC"
                          />
                          <Bar stackId="a" dataKey="Low" fill="#FFD773" />
                          <Bar stackId="a" dataKey="Medium" fill="#FFB000" />
                          <Bar stackId="a" dataKey="High" fill="#F17B00" />
                          <Bar stackId="a" dataKey="Severe" fill="#FF4100" />
                          <Bar stackId="a" dataKey="Critical" fill="#FF0000" />
                        </BarChart>
                      </ResponsiveContainer>
                    </Paper>
                  </Grid>
                );
              })}
          </TabPanel>
          <TabPanel
            style={{ minHeight: 800, width: '100%', paddingTop: 20 }}
            value={tabValue}
            index={4}
          >
            <Grid item={true}>
              <Paper
                elevation={2}
                style={{
                  height: 750,
                  width: '100%',
                  marginBottom: 40,
                }}
              >
                {trendingChatData &&
                  <ResponsiveContainer width="100%" height="90%">
                    <LineChart width={500} height={500}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="category"
                        type="category"
                        allowDuplicatedCategory={false}
                        tick={{ fill: 'white' }}
                        interval={"preserveStartEnd"}
                      />
                      <YAxis dataKey="value" tick={{ fill: 'white' }} />
                      <Tooltip />
                      <Legend
                        onClick={this.handleTrendingClick.bind(this)}
                        onMouseEnter={this.handleMouseEnter.bind(this)}
                        onMouseLeave={this.handleMouseLeave.bind(this)}
                        wrapperStyle={{ bottom: -20 }}
                      />
                      {trendingChatData.map((s, index) => (
                        <Line
                          dataKey="value"
                          isAnimationActive={trendingName === s.name ? false : true}
                          data={s.data}
                          hide={trendingData.includes(s.name) && true}
                          strokeWidth={3}
                          name={s.name}
                          key={s.name}
                          dot={{ r: 8 }}
                          activeDot={{ r: 8 }}
                          stroke={colorsForTrendingChart[index]}
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
