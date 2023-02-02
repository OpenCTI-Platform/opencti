/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import ReactHtmlParser from 'react-html-parser';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import Button from '@material-ui/core/Button';
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import CardContent from '@material-ui/core/CardContent';
import { withStyles } from '@material-ui/core/styles';
import moment from 'moment';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Chip from '@material-ui/core/Chip';
import Dialog from '@material-ui/core/Dialog';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Box from '@material-ui/core/Box';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import CircularProgress from '@material-ui/core/CircularProgress';
import Skeleton from '@material-ui/lab/Skeleton';
import { fetchScan } from '../../../services/scan.service';
import {
  fetchAnalysis,
  getAnalysisHosts,
  getAnalysisSoftware,
  getAnalysisWeaknesses,
  getAnalysisFilteredResultsWeakness,
  getAnalysisVulnerabilities,
  getAnalysisFilteredResults,
  getAnalysisFilteredResultsDetails,
  getAnalysisFilteredResultsVulnerability,
  createVulnerabilityAssessmentReport,
} from '../../../services/analysis.service';
import Hosts from './components/Hosts';
import Products from './components/Products';
import VulnerabilityAccordionCards from './components/VulnerabilityAccordionCards';
import WeaknessAccordionCards from './components/WeaknessAccordionCards';
import inject18n from '../../../components/i18n';

import GenerateReport from './modals/GenerateReport';

import Loader from '../../../components/Loader';

const styles = (theme) => ({
  selectedTableRow: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: 'rgba(3, 45, 105)',
    },
  },
});

function TabPanel(props) {
  const {
    children,
    value,
    index,
    ...other
  } = props;

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

class ExploreResults extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { exploreResultId },
      },
    } = props;

    this.state = {
      client_ID: (exploreResultId || null),
      client: null,
      analysis: null,
      scan: null,
      hosts: null,
      software: null,
      filteredResultsParams: {},
      filteredResultsData: null,
      filteredResultsDataDetails: null,
      currentResult: null,
      tabValue: 0,
      weaknessAccordion: false,
      weaknessDetails: null,
      vulnerabilitiesAccordion: false,
      vulnerabilitiesDetails: null,
      selectedRow: {},
      host_ip: null,
      cpe: null,
      cve_id: null,
      cwe_id: null,
      generateReportSuccess: false,
      openDialog: false,
    };
  }

  componentDidMount() {
    this.setState({ client: localStorage.getItem('client_id') }, function () {
      this.refreshAnalyses();
    });
  }

  refreshAnalyses() {
    fetchAnalysis(this.state.client_ID, this.state.client)
      .then((response) => {
        this.setState({ analysis: response.data });

        fetchScan(response.data.scan.id, this.state.client)
          .then((response) => {
            this.setState({ scan: response.data });
          })
          .catch((error) => {
            console.log(error);
          });

        if (this.state.client) {
          this.resetAllData();
        }
      })
      .catch((error) => {
        console.log(error);
      });
  }

  resetAllData() {
    getAnalysisHosts(this.state.analysis.id, this.state.client)
      .then((response) => {
        this.setState({ hosts: response.data });
      })
      .catch((error) => {
        console.log(error);
      });

    getAnalysisSoftware(this.state.analysis.id, this.state.client)
      .then((response) => {
        this.setState({ software: response.data });
      })
      .catch((error) => {
        console.log(error);
      });

    getAnalysisWeaknesses(this.state.analysis.id, this.state.client)
      .then((response) => {
        this.setState({ weakness: response.data });
      })
      .catch((error) => {
        console.log(error);
      });

    getAnalysisVulnerabilities(this.state.analysis.id, this.state.client)
      .then((response) => {
        this.setState({ vulnerabilities: response.data });
      })
      .catch((error) => {
        console.log(error);
      });
  }

  render() {
    const { classes } = this.props;
    const {
      client,
      analysis,
      hosts,
      software,
      weakness,
      vulnerabilities,
      filteredResultsParams,
      filteredResultsData,
      filteredResultsDataDetails,
      currentResult,
      tabValue,
      weaknessAccordion,
      weaknessDetails,
      vulnerabilitiesAccordion,
      vulnerabilitiesDetails,
      selectedRow,
      host_ip,
      cpe,
      cve_id,
      cwe_id,
      generateReportSuccess,
      openDialog,
    } = this.state;

    const handleFilterResults = (params, name, type) => {
      this.setState({ filteredResultsData: 'loading' });

      if (params.host_ip) {
        this.setState(
          { host_ip: params.host_ip },
          handleGetAnalysisFilteredResults(params, type),
        );

        this.setState({ selectedRow: { ...this.state.selectedRow, host_ip: name } });
      }
      if (params.cpe) {
        this.setState(
          { cpe: params.cpe },
          handleGetAnalysisFilteredResults(params, type),
        );

        this.setState({ selectedRow: { ...this.state.selectedRow, cpe: name } });
      }
      if (params.cwe_id) {
        this.setState(
          { cwe_id: params.cwe_id },
          handleGetAnalysisFilteredResults(params, type),
        );

        this.setState({ selectedRow: { ...this.state.selectedRow, cwe_id: name } });
      }
      if (params.cve_id) {
        this.setState(
          { cve_id: params.cve_id },
          handleGetAnalysisFilteredResults(params, type),
        );
        this.setState({ selectedRow: { ...this.state.selectedRow, cve_id: name } });
      }
    };

    const handleGetAnalysisFilteredResults = (params, type) => {
      getAnalysisFilteredResults(this.state.analysis.id, this.state.client, {
        host_ip: params.host_ip || host_ip,
        cpe: params.cpe || cpe,
        cwe_id: params.cwe_id || cwe_id,
        cve_id: params.cve_id || cve_id,
      })
        .then((response) => {
          this.setState({ filteredResultsData: response.data });

          if (params.host_ip) {
            const currentResult = response.data.find((element) => element.host_ip === params.host_ip);
            this.setState({ currentResult });
          }

          const detailParams = {
            ...(params.host_ip && { host_ip: params.host_ip }),
            ...(params.cpe && { cpe: params.cpe }),
            ...(params.cve_id && { cve_id: params.cve_id }),
            ...(params.cwe_id && { cwe_id: params.cwe_id }),
          };

          handleFilterResultsDetails(
            this.state.analysis.id,
            this.state.client,
            detailParams,
          );
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisHosts(this.state.analysis.id, this.state.client, {
        host_ip: params.host_ip || host_ip,
        cpe: params.cpe || cpe,
        cwe_id: params.cwe_id || cwe_id,
        cve_id: params.cve_id || cve_id,
      })
        .then((response) => {
          this.setState({ hosts: response.data });
        })
        .catch((error) => {
          console.log(error);
        });
      getAnalysisSoftware(this.state.analysis.id, this.state.client, {
        host_ip: params.host_ip || host_ip,
        cpe: params.cpe || cpe,
        cwe_id: params.cwe_id || cwe_id,
        cve_id: params.cve_id || cve_id,
      })
        .then((response) => {
          this.setState({ software: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisWeaknesses(
        this.state.analysis.id,
        this.state.client,
        {
          host_ip: params.host_ip || host_ip,
          cpe: params.cpe || cpe,
          cwe_id: params.cwe_id || cwe_id,
          cve_id: params.cve_id || cve_id,
        },
      )
        .then((response) => {
          this.setState({ weakness: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisVulnerabilities(
        this.state.analysis.id,
        this.state.client,
        {
          host_ip: params.host_ip || host_ip,
          cpe: params.cpe || cpe,
          cwe_id: params.cwe_id || cwe_id,
          cve_id: params.cve_id || cve_id,
        },
      )
        .then((response) => {
          this.setState({ vulnerabilities: response.data });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const handleFilterResultsDetails = (id, client, params) => {
      getAnalysisFilteredResultsDetails(id, client, params)
        .then((response) => {
          this.setState({ filteredResultsDataDetails: response.data });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const handleTabChange = (event, newValue) => {
      this.setState({ tabValue: newValue });
    };

    const handleWeaknessAccordion = (panel, params) => (event, isExpanded) => {
      this.setState({ weaknessAccordion: isExpanded ? panel : false });
      this.setState({ weaknessDetails: '' });
      getAnalysisFilteredResultsWeakness(
        this.state.analysis.id,
        this.state.client,
        params,
      )
        .then((response) => {
          this.setState({ weaknessDetails: response.data });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const handleWeaknessClick = (params, name) => {
      getAnalysisHosts(this.state.analysis.id, this.state.client, params)
        .then((response) => {
          this.setState({ hosts: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisSoftware(this.state.analysis.id, this.state.client, params)
        .then((response) => {
          this.setState({ software: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisWeaknesses(this.state.analysis.id, this.state.client, params)
        .then((response) => {
          this.setState({ weakness: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      getAnalysisVulnerabilities(
        this.state.analysis.id,
        this.state.client,
        params,
      )
        .then((response) => {
          this.setState({ vulnerabilities: response.data });
        })
        .catch((error) => {
          console.log(error);
        });

      handleFilterResults(params, name);
    };

    const handleVulnerabilitiesAccordion = (panel, params) => (event, isExpanded) => {
      this.setState({ vulnerabilitiesAccordion: isExpanded ? panel : false });
      this.setState({ vulnerabilitiesDetails: '' });
      getAnalysisFilteredResultsVulnerability(
        this.state.analysis.id,
        this.state.client,
        params,
      )
        .then((response) => {
          this.setState({ vulnerabilitiesDetails: response.data });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const onGenerateReport = (id, client, params) => {
      createVulnerabilityAssessmentReport(id, client, params)
        .then((response) => {
          this.setState({ generateReportSuccess: true });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const handleDialogOpen = () => {
      this.setState({ openDialog: true });
    };

    const handleDialogClose = () => {
      this.setState({ openDialog: false });
    };

    const handleReset = () => {
      this.setState({ weaknessDetails: null });
      this.setState({ weaknessAccordion: false });
      this.setState({ selectedRow: {} });
      this.setState({ currentResult: null });
      this.setState({ filteredResultsParams: {} });
      this.setState({ filteredResultsData: null });
      this.setState({ filteredResultsDataDetails: null });
      this.setState({ vulnerabilitiesDetails: null });
      this.setState({ vulnerabilitiesAccordion: false });
      this.setState({ host_ip: null });
      this.setState({ cpe: null });
      this.setState({ cve_id: null });
      this.setState({ cwe_id: null });
      this.resetAllData();
    };

    return (
      <div>
        {this.state.analysis && this.state.scan ? (
          <>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <Typography variant="h1" component="h2" gutterBottom>
                  {`${analysis.scan.scan_name}: ${moment(
                    analysis.completed_date,
                  ).fromNow()}`}
                </Typography>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Chip size="small" style={{ margin: 3 }} label="Top 4" />
                  <Chip
                    size="small"
                    style={{ margin: 3 }}
                    label="Previous 33 Years"
                  />
                  {analysis.completed_date && (
                    <Chip
                      size="small"
                      style={{ margin: 3 }}
                      label={moment(analysis.completed_date).fromNow()}
                    />
                  )}
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
                  <Button
                    size="medium"
                    variant="contained"
                    style={{ margin: 3, marginLeft: 'auto' }}
                    disabled={selectedRow == null}
                    onClick={handleReset}
                  >
                    Reset Filters
                  </Button>
                  <Button
                    size="medium"
                    variant="contained"
                    style={{ margin: 3 }}
                    onClick={handleDialogOpen}
                  >
                    Generate Report
                  </Button>
                </div>
              </Grid>
            </Grid>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={4}>
                {hosts && (
                  <Hosts
                    hosts={hosts}
                    action={handleFilterResults}
                    selectedRow={selectedRow}
                  />
                )}
                {software && (
                  <Products
                    software={software}
                    action={handleFilterResults}
                    selectedRow={selectedRow}
                  />
                )}
                {weakness && (
                  <WeaknessAccordionCards
                    weakness={weakness}
                    action={handleFilterResults}
                    selectedRow={selectedRow}
                  />
                )}
                {vulnerabilities && (
                  <VulnerabilityAccordionCards
                    vulnerabilities={vulnerabilities}
                    action={handleFilterResults}
                    selectedRow={selectedRow}
                  />
                )}
              </Grid>
              <Grid item={true} xs={8}>
                <Grid container spacing={3}>
                  <Grid item={true} xs={12}>
                <Typography variant="h4" gutterBottom={true}>
                  Filtered Results
                </Typography>
                <Paper elevation={2} style={{ minHeight: 350 }}>
                  <TableContainer style={{ maxHeight: 325 }}>
                    <Table stickyHeader size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Score</TableCell>
                          <TableCell>Records</TableCell>
                          <TableCell>Host IP</TableCell>
                          <TableCell>Product</TableCell>
                          <TableCell>Solution</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                            {filteredResultsData === 'loading' ? (
                              <CircularProgress
                                style={{
                                  position: 'absolute',
                                  left: '50%',
                                  top: '50%',
                                }}
                            />
                            ) : filteredResultsData ? (
                              filteredResultsData.map((result, i) => {
                                const rowName = `resultsRow-${i}`;

                                return (
                              <TableRow
                                key={rowName}
                                selected={rowName === selectedRow}
                                onClick={() =>
                                  handleFilterResults(
                                    { host_ip: result.host_ip },
                                    rowName,
                                  )
                                }
                                hover
                                classes={{ root: classes.selectedTableRow }}
                              >
                                <TableCell component="th" scope="row">
                                  {result.score}
                                </TableCell>
                                <TableCell>{result.records}</TableCell>
                                <TableCell>{result.host_ip}</TableCell>
                                <TableCell>{result.software}</TableCell>
                                <TableCell>{result.solution}</TableCell>
                              </TableRow>
                                );
                              })
                            ) : (
                          <div>No filters selected.</div>
                            )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
                  </Grid>
                </Grid>
                <Grid container spacing={3}>
                  <Grid item={true} xs={8}>
                    <Typography variant="h4" gutterBottom={true}>
                      Solutions
                    </Typography>
                    <div style={{ maxHeight: 250, overflow: 'auto' }}>
                      {ReactHtmlParser(filteredResultsDataDetails?.solution)}
                    </div>
                    <Tabs value={tabValue} onChange={handleTabChange}>
                      <Tab label="Problem Details" {...a11yProps(0)} />
                      <Tab label="Weaknesses" />
                      <Tab label="Vulnerabilities" />
                    </Tabs>
                    <TabPanel
                      style={{ maxHeight: 700, maxWidth: 800, overflowY: 'auto', overflowX: 'hidden' }}
                      value={tabValue}
                      index={0}
                    >
                      <Typography variant="h4" gutterBottom={true}>
                        Problems
                      </Typography>
                      {filteredResultsDataDetails?.details.map((i, j) => (
                        <p key={j}>{ReactHtmlParser(i)}</p>
                      ))}
                      {filteredResultsDataDetails?.plugins.map((i, j) => (
                        <p key={j}>{ReactHtmlParser(i)}</p>
                      ))}
                      <Typography variant="h4" gutterBottom={true}>
                        Exploitable?
                      </Typography>
                      {filteredResultsDataDetails?.exploit_frameworks.map(
                        (i, j) => (
                          <p key={j}>{ReactHtmlParser(i)}</p>
                        ),
                      )}
                      <Typography variant="h4" gutterBottom={true}>
                        Details
                      </Typography>
                      {filteredResultsDataDetails?.problems.map((i, j) => (
                        <p key={j}>{ReactHtmlParser(i)}</p>
                      ))}
                    </TabPanel>
                    <TabPanel value={tabValue} index={1}>
                      {weakness?.map((i, j) => (
                        <Accordion
                          key={j}
                          expanded={weaknessAccordion === 'panel-' + j}
                          onChange={handleWeaknessAccordion('panel-' + j, {
                            cwe_id: i.cwe_id,
                          })}
                        >
                          <AccordionSummary
                            expandIcon={<ExpandMoreIcon />}
                            aria-controls="panel1a-content"
                            id="panel1a-header"
                          >
                            <Typography>
                              {i.cwe_id}: {i.tooltip}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            {weaknessDetails?.description ? (
                              <Typography>
                                {weaknessDetails?.description}
                              </Typography>
                            ) : (
                              <CircularProgress />
                            )}
                          </AccordionDetails>
                        </Accordion>
                      ))}
                    </TabPanel>
                    <TabPanel value={tabValue} index={2}>
                      {vulnerabilities?.map((i, j) => (
                        <Accordion
                          key={j}
                          expanded={vulnerabilitiesAccordion === 'panel-' + j}
                          onChange={handleVulnerabilitiesAccordion(
                            'panel-' + j,
                            {
                              cve_id: i.cve_id,
                            },
                          )}
                        >
                          <AccordionSummary
                            expandIcon={<ExpandMoreIcon />}
                            aria-controls="panel1a-content"
                            id="panel1a-header"
                          >
                            <Typography>{i.cve_id}</Typography>
                          </AccordionSummary>
                          <AccordionDetails style={{ display: 'block' }}>
                            <div style={{ marginBottom: '10px' }}>
                              <Typography variant="h4" gutterBottom={true}>
                                Publish Date:
                              </Typography>
                              <p>{vulnerabilitiesDetails?.pub_date}</p>
                            </div>
                            <div style={{ marginBottom: '10px' }}>
                              <Typography variant="h4" gutterBottom={true}>
                                CVSS2 Base Score:
                              </Typography>
                              <p>
                                {vulnerabilitiesDetails?.v2_base}{' '}
                                {vulnerabilitiesDetails?.v2_vector}
                              </p>
                            </div>
                            <div style={{ marginBottom: '10px' }}>
                              <Typography variant="h4" gutterBottom={true}>
                                CVSS3 Base Score:
                              </Typography>
                              <p>
                                {vulnerabilitiesDetails?.v3_base}{' '}
                                {vulnerabilitiesDetails?.v3_vector}
                              </p>
                            </div>
                            <div style={{ marginBottom: '10px' }}>
                              <Typography variant="h4" gutterBottom={true}>
                                Description
                              </Typography>
                              {ReactHtmlParser(
                                vulnerabilitiesDetails?.description,
                              )}
                            </div>
                          </AccordionDetails>
                        </Accordion>
                      ))}
                    </TabPanel>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography variant="h4" gutterBottom={true}>
                      Host Info
                    </Typography>
                    <Card>
                      <CardContent>
                        <div>
                          <Typography variant="h3" gutterBottom={true}>
                            IP Address
                          </Typography>
                          <p>{currentResult?.host_ip}</p>
                        </div>
                        <div>
                          <Typography variant="h3" gutterBottom={true}>
                            Hostname
                          </Typography>
                          <p>{currentResult?.host_name}</p>
                        </div>
                        <div>
                          <Typography variant="h3" gutterBottom={true}>
                            MAC Address
                          </Typography>
                          <p>{currentResult?.host_mac}</p>
                        </div>
                        <div>
                          <Typography variant="h3" gutterBottom={true}>
                            Operating System
                          </Typography>
                          <p>{currentResult?.host_os}</p>
                        </div>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
            <Dialog
              open={openDialog}
              onClose={() => handleDialogClose()}
              maxWidth="md"
            >
              <GenerateReport
                id={analysis.id}
                client={client}
                scanName={analysis.scan.scan_name}
                success={generateReportSuccess}
                onClose={handleDialogClose}
                action={onGenerateReport}
              />
            </Dialog>
          </>
        ) : (
          <Loader />
        )}
      </div>
    );
  }
}

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ExploreResults);
