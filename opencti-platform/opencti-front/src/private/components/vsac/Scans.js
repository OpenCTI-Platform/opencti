/* eslint-disable */
import React, { Component } from "react";
import * as PropTypes from "prop-types";
import { withRouter } from "react-router-dom";
import * as R from "ramda";
import {
  buildViewParamsFromUrlAndStorage,
} from "../../../utils/ListParameters";
import { truncate } from "../../../utils/String";
import percentage from "../../../utils/percentage";
import inject18n from "../../../components/i18n";
import NewAnalysis from "./modals/NewAnalysis";
import Delete from "./modals/Delete";
import ExportCSV from "./modals/ExportCSV";
import GenerateReport from "./modals/GenerateReport";
import VulnerabilityScan from "./modals/VulnerabilityScan";
import DescriptionIcon from "@material-ui/icons/Description";
import AddIcon from "@material-ui/icons/Add";
import ExploreIcon from "@material-ui/icons/Explore";
import ShowChartIcon from "@material-ui/icons/ShowChart";
import DeleteIcon from "@material-ui/icons/Delete";
import IconButton from "@material-ui/core/IconButton";
import CloudUploadIcon from "@material-ui/icons/CloudUpload";
import ArrowDropDownIcon from "@material-ui/icons/ArrowDropDown";
import ImportExportIcon from "@material-ui/icons/ImportExport";
import CompareIcon from "@material-ui/icons/Compare";
import ScannerIcon from "@material-ui/icons/Scanner";
import EditIcon from "@material-ui/icons/Edit";
import PublishIcon from "@material-ui/icons/Publish";
import Popover from '@material-ui/core/Popover';
import Button from "@material-ui/core/Button";
import CardHeader from "@material-ui/core/CardHeader";
import CardActions from "@material-ui/core/CardActions";
import LinearProgress from '@material-ui/core/LinearProgress';
import Grid from "@material-ui/core/Grid";
import Paper from "@material-ui/core/Paper";
import List from "@material-ui/core/List";
import ListItem from "@material-ui/core/ListItem";
import ListItemIcon from "@material-ui/core/ListItemIcon";
import ListItemText from "@material-ui/core/ListItemText";
import ListItemSecondaryAction from "@material-ui/core/ListItemSecondaryAction";
import Typography from "@material-ui/core/Typography";
import CardContent from "@material-ui/core/CardContent";
import { deleteScan, fetchAllScans } from "../../../services/scan.service";
import {
  fetchAllAnalysis,
  getAnalysisSummary,
  exportAnalysisCsv,
  deleteAnalysis,
  createNewScanAnalysis,
  createVulnerabilityAssessmentReport,
} from "../../../services/analysis.service";
import MoreVertIcon from "@material-ui/icons/MoreVert";
import Menu from "@material-ui/core/Menu";
import MenuItem from "@material-ui/core/MenuItem";
import moment from "moment";
import Dialog from "@material-ui/core/Dialog";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  ReferenceLine,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import Chip from "@material-ui/core/Chip";
import { toastSuccess } from "../../../utils/bakedToast";
import DeleteScanVerify from "./modals/DeleteScanVerify";
import CircularProgress from '@material-ui/core/CircularProgress';
import UpdateScan from "./modals/UpdateScan";
import { Box, Card } from "@material-ui/core";
import { withTheme, withStyles } from '@material-ui/core/styles';

const styles = (theme) => ({
  root: {
    marginTop: '1rem',
  },
  card: {
    width: "100%",
    marginBottom: 20,
    borderRadius: 6,
    position: "relative",
  },
  cardHeader: {
    marginBottom: "0",
  },
  paper: {
    margin: "10px 0 0 0",
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    paddingRight: 24,
  },
  itemIconSecondary: {
    marginRight: 0,
  },
  number: {
    marginTop: 10,
    float: "left",
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: "uppercase",
    fontSize: 12,
    fontWeight: 500,
  },
  icon: {
    position: "absolute",
    top: 35,
    right: 20,
  },
  graphContainer: {
    width: "100%",
    padding: "20px 20px 0 0",
  },
  labelsCloud: {
    width: "100%",
    height: 300,
  },
  label: {
    width: "100%",
    height: 100,
    padding: 15,
  },
  labelNumber: {
    fontSize: 30,
    fontWeight: 500,
  },
  labelValue: {
    fontSize: 15,
  },
  itemAuthor: {
    width: 200,
    minWidth: 200,
    maxWidth: 200,
    paddingRight: 24,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    textAlign: "left",
  },
  itemType: {
    width: 100,
    minWidth: 100,
    maxWidth: 100,
    paddingRight: 24,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    textAlign: "left",
  },
  itemDate: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    paddingRight: 24,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    textAlign: "left",
  },
  popoverContainer: { width: '40rem', padding: "3%", backgroundColor: 'rgb(56,64,87)' },
  popoverItems: { margin: "1% 0" },
  popoverHeader: { color: 'rgb(146,150,163)', marginBottom: '0.5em' }

})

const ScanSortBy = {
  UploadDate: 0,
  ScanDate: 1
}

class Scans extends Component {

  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-reports${props.objectId ? `-${props.objectId}` : ""}`
    );
    this.state = {
      sortBy: R.propOr("published", "sortBy", params),
      orderAsc: R.propOr(false, "orderAsc", params),
      searchTerm: R.propOr("", "searchTerm", params),
      view: R.propOr("lines", "view", params),
      filters: R.propOr({}, "filters", params),
      client_ID: null,
      openExports: false,
      numberOfElements: { number: 0, symbol: "" },
      selectedElements: null,
      selectAll: false,
      loadingScans: true,
      loadingAnalyses: true,
      dialogParams: null,
      vulnerabilityAnchorEl: null,
      sortByAnchorEl: null,
      popoverAnchorEl: null,
      analysisAnchorEl: null,
      renderScans: null,
      scanSortBy: ScanSortBy.ScanDate,
      sortByLabel: "Scan Date",
      openDialog: false,
      openScanMenu: false,
      loadDialog: null,
      openedPopoverId: null,
      pendingAnalysis: null,
      scanAssociation: {},
      analysisLoaderNoDisplay: true,
    };
  }

  sortScans(scans, scanSortBy) {
    let sortedScans = scans;
    if (scanSortBy === ScanSortBy.ScanDate) {
      sortedScans = scans.slice().sort((a, b) => new Date(b.report_date) - new Date(a.report_date))
    } else if (scanSortBy === ScanSortBy.UploadDate) {
      sortedScans = scans.slice().sort((a, b) => new Date(b.upload_date) - new Date(a.upload_date))
    }
    return sortedScans
  }

  refreshScans(refreshInBackground) {
    this.setState({ loadingScans: true });
    fetchAllScans(this.state.client_ID)
      .then((response) => {
        const newScans = response.data;
        if (refreshInBackground) {

          if (JSON.stringify(this.state.renderScans) !== JSON.stringify(newScans)) {
            this.setState({ renderScans: this.sortScans(newScans, this.state.scanSortBy) });
            clearInterval(this.state.refreshIntervalId);

          }
        } else {
          this.setState({ renderScans: this.sortScans(newScans, this.state.scanSortBy) });
        }

        this.setState({ loadingScans: false });
      })
      .catch((error) => {
        console.log(error);
      });
  }

  refreshAnalyses(refreshInBackground) {
    const prevAnalysis = this.state.analyses;

    fetchAllAnalysis(this.state.client_ID)
      .then((response) => {
        let newAnalyses = response.data;
        let scatterPlotData = {};
        const associationTable = {}

        newAnalyses.forEach(analysis => {
          let associations = associationTable[analysis.scan.id]
          if (associations === undefined) {
            associations = 1
          } else {
            associations++
          }
          associationTable[analysis.scan.id] = associations

          getAnalysisSummary(analysis.id, this.state.client_ID)
            .then((response) => {

              let scatterPlot = [];
              response.data.forEach((item) => {
                if (item.cwe_name) {
                  scatterPlot.push({ cwe_name: item.cwe_name, x: item.host_percent, y: item.score, score: item.score, host_count_total: item.host_count });
                }
              });
              if (scatterPlot.length === 0) return;
              scatterPlotData[analysis.id] = scatterPlot;

            })
            .catch((error) => {
              console.log(error);
            })
        })

        if (refreshInBackground) {
          if (JSON.stringify(prevAnalysis) !== JSON.stringify(newAnalyses)) {
            this.setState({ analysisLoaderNoDisplay: true });
            this.setState({ analyses: newAnalyses });
            this.setState({ scanAssociation: associationTable });
            this.setState({ scatterPlotData: scatterPlotData }, function () { });
            setTimeout(() => { this.setState({ analysisLoaderNoDisplay: false }) }, 3000);

            clearInterval(this.state.refreshIntervalId);
          }
        } else {
          this.setState({ analysisLoaderNoDisplay: true })
          this.setState({ scanAssociation: associationTable })
          this.setState({ analyses: newAnalyses });
          this.setState({ scatterPlotData: scatterPlotData });
          setTimeout(() => { this.setState({ analysisLoaderNoDisplay: false }) }, 3000);
        }

        this.setState({ loadingAnalyses: false });
      })
      .catch((error) => {
        console.log(error);
      });
  };

  componentDidMount() {
    this.setState({ client_ID: localStorage.getItem('client_id') }, function () {
      this.refreshScans(false)
      this.refreshAnalyses(false)
    });
  }

  componentWillUnmount() {
    clearInterval(this.state.refreshIntervalId)
  }

  render() {

    const { t, classes } = this.props;
    const {
      client_ID,
      loadingScans,
      renderScans,
      sortByLabel,
      loadingAnalyses,
      analyses,
      scatterPlotData,
      openDialog,
      openScanMenu,
      dialogParams,
      popoverAnchorEl,
      analysisAnchorEl,
      sortByAnchorEl,
      openedPopoverId,
      openAnalysisMenu,
      pendingAnalysis,
      scanAssociation,
      analysisLoaderNoDisplay,
    } = this.state;

    const handlePopoverOpen = (event, popoverId) => {
      this.setState({ popoverAnchorEl: event.currentTarget, openedPopoverId: popoverId });
    };

    const handlePopoverClose = () => {
      this.setState({ popoverAnchorEl: null, openedPopoverId: null });
    };

    const handleSortByClick = (event) => {
      this.setState({ sortByAnchorEl: event.currentTarget });
    };

    const handleAnalysisClick = (event, analysis_id) => {
      this.setState({ analysisAnchorEl: event.currentTarget, openAnalysisMenu: analysis_id });
    };

    const handleScanClick = (event, scan_id) => {
      handlePopoverClose()
      this.setState({ vulnerabilityAnchorEl: event.currentTarget, openScanMenu: scan_id })
    }

    const triggerPageRefreshInterval = () => {
      this.refreshScans(false);
      this.refreshAnalyses(false);
      const intervalId = setInterval(() => {
        this.refreshScans(true);
        this.refreshAnalyses(true);
      }, 30000)
      this.setState({ refreshIntervalId: intervalId });
    }

    const sortByScanDate = () => {
      this.setState({ sortByLabel: "Scan Date" });
      this.setState({ scanSortBy: ScanSortBy.ScanDate })
      this.setState({ renderScans: this.sortScans(renderScans, ScanSortBy.ScanDate) });
      this.setState({ sortByAnchorEl: null });
    };

    const sortByUploadDate = () => {
      this.setState({ sortByLabel: "Upload Date" });
      this.setState({ scanSortBy: ScanSortBy.UploadDate })
      this.setState({ renderScans: this.sortScans(renderScans, ScanSortBy.UploadDate) });
      this.setState({ sortByAnchorEl: null });
    };

    const handleDialogOpen = (dialogParams) => {
      this.setState({ openDialog: true });
      this.setState({ dialogParams: dialogParams });
      this.setState({ vulnerabilityAnchorEl: null, openScanMenu: null });
      this.setState({ analysisAnchorEl: null });
      this.setState({ analysisByAnchorEl: null, openAnalysisMenu: null });
    };

    const handleDialogClose = () => {
      this.setState({ openDialog: false });
      this.setState({ openScanMenu: null })
      this.setState({ openAnalysisMenu: null });
    };

    const handleLinkClink = (path, data) => {
      this.props.history.push({
        pathname: path,
        state: data
      });
    }

    const getCurrentScan = (id, scans) => {
      const scan = scans.find((i) => i.id === id);
      if (scan) {
        return scan;
      }
    }

    const onNewAnalysis = (id, client, params) => {
      const scanName = renderScans.filter((s) => s.id === params.scan_id)[0].scan_name
      createNewScanAnalysis(id, client, params)
        .then((response) => {
          toastSuccess("Creating New Analysis")
          handleDialogClose();
          this.setState({ pendingAnalysis: scanName })
          setTimeout(() => {
            this.refreshAnalyses()
            this.setState({ pendingAnalysis: null })
          }, 10000);
        })
        .catch((error) => {
          console.log(error);
        });

    };

    const onGenerateReport = (id, client, params) => {
      createVulnerabilityAssessmentReport(id, client, params)
        .then((response) => {
          toastSuccess("Report Request Submitted")
          this.setState({
            dialogParams: {
              modal: "Generate Report",
              success: true,
            },
          });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const onDeleteAnalysis = (id, client) => {
      deleteAnalysis(id, client)
        .then((response) => {
          toastSuccess("Analysis Deleted")
          handleDialogClose();
          this.refreshAnalyses();
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const onExportAnalysis = (id, client) => {
      this.setState({
        dialogParams: { modal: "Export Data", isLoading: true },
      });
      exportAnalysisCsv(id, client)
        .then((response) => {
          toastSuccess("Export Request Submitted")
          this.setState({
            dialogParams: {
              modal: "Export Data",
              isLoading: false,
              success: true,
            },
          });
        })
        .catch((error) => {
          console.log(error);
        });
    };

    const rerenderParentCallback = () => {
      triggerPageRefreshInterval();
    }

    const handleDeleteScan = (event, id) => {
      const associations = scanAssociation[id];
      if (associations === undefined) {
        deleteScan(id, client_ID)
          .then(() => {
            this.refreshScans(false)
          })
          .catch((err) => console.log(err))
      } else {
        const analysesToDelete = this.state.analyses.filter((a) => a.scan.id === id)
        handleDialogOpen({
          modal: "Scan Delete Verify",
          clientId: client_ID,
          scan: this.state.renderScans.filter((s) => s.id === id)[0],
          analyses: analysesToDelete,
          action: onDeleteComplete
        })
      }
    }

    const onDeleteComplete = () => {
      handleDialogClose()
      this.refreshScans(false)
      this.refreshAnalyses(false)
    }

    const renderDialogSwitch = () => {
      switch (this.state.dialogParams.modal) {
        case "New Analysis":
          return (
            <NewAnalysis
              id={this.state.dialogParams.id} // Scan ID
              isScan={this.state.dialogParams.isScan}
              client={this.state.dialogParams.client}
              onClose={handleDialogClose}
              action={onNewAnalysis}
            />
          );
        case "Generate Report":
          return (
            <GenerateReport
              id={this.state.dialogParams.id}
              client={this.state.dialogParams.client}
              scanName={this.state.dialogParams.scanName}
              success={this.state.dialogParams.success}
              onClose={handleDialogClose}
              action={onGenerateReport}
            />
          );
        case "Export Data":
          return (
            <ExportCSV
              id={this.state.dialogParams.id}
              client={this.state.dialogParams.client}
              isLoading={this.state.dialogParams.isLoading}
              success={this.state.dialogParams.success}
              onClose={handleDialogClose}
              action={onExportAnalysis}
            />
          );
        case "Delete Data":
          return (
            <Delete
              id={this.state.dialogParams.id}
              client={this.state.dialogParams.client}
              date={this.state.dialogParams.date}
              onClose={handleDialogClose}
              action={onDeleteAnalysis}
            />
          );
        case "Vulnerability Scan":
          return <VulnerabilityScan
            client_ID={this.state.client_ID}
            rerenderParentCallback={rerenderParentCallback}
            onClose={handleDialogClose}
          />;
        case "Scan Delete Verify":
          return <DeleteScanVerify
            clientId={this.state.dialogParams.clientId}
            scan={this.state.dialogParams.scan}
            analyses={this.state.dialogParams.analyses}
            onComplete={this.state.dialogParams.action}
            onClose={handleDialogClose}
          />
        case "Edit Scan":
          return <UpdateScan
            onClose={(success) => {
              if (success) {
                this.refreshScans()
              }
              handleDialogClose()
            }}
            clientId={this.state.client_ID}
            scan={this.state.dialogParams.scan}
          />
        default:
          return;
      }
    };

    const CustomTooltip = ({ active, payload, label }) => {
      if (active && payload && payload.length) {
        return (
          <div
            className="custom-tooltip"
            style={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', fontSize: 12, borderRadius: 10, border: 1, padding: 10 }}>
            <p className="label" style={{ paddingBottom: 5 }}>{payload[0].payload.cwe_name}</p>
            <p className="weakness" style={{ paddingBottom: 5 }}>{`Weakness Score: ${payload[0].payload.score}`}</p>
            <p className="host" style={{ paddingBottom: 5 }}>{`Hosts with Weakness: ${payload[0].payload.host_count_total} (${payload[0].payload.x}%)`}</p>
          </div>
        );
      }
      return null;
    };

    return (
      <div className={classes.root}>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Typography variant="h4" gutterBottom={true}>
              {t("How Your Vulnerabilities are Prioritized")}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              elevation={2}
              style={{ height: 350, marginBottom: 20 }}
            >
              <CardContent>
                <p>
                  Your software and hardware keep your enterprise running.
                  Software and hardware have weaknesses, and those weaknesses
                  have vulnerabilities. The underlying weaknesses in your system
                  are the target of the adversary attacks.
                </p>
                <p>
                  What is the likelihood that a weakness will be exploited? What
                  are the consequences if it is exploited? These two factors are
                  considered when your vulnerabilities are examined.
                  Vulnerabilities with a lower probability of being exploited
                  are discounted. Weaknesses that have severe negative business
                  consequences are escalated.
                </p>
                <p>
                  For further technical information visit{" "}
                  <a
                    href="https://cwe.mitre.org/cwraf/introduction.html"
                    rel="noopener noreferrer"
                    target="_blank"
                  >
                    cwe.mitre.org
                  </a>
                </p>
              </CardContent>
            </Paper>
          </Grid>
          <Grid item={true} xs={8}>
            <Typography variant="h4" gutterBottom={true}>
              {t("Vulnerability Scans")}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              elevation={2}
              style={{ height: 350 }}
            >
              <CardContent style={{ height: 290, overflow: "hidden" }}>
                <CardHeader
                  style={{ padding: 0 }}
                  action={
                    <div>
                      <Button
                        color="primary"
                        style={{ marginTop: 0, marginBottom: 0 }}
                        className={classes.button}
                        endIcon={<ArrowDropDownIcon />}
                        onClick={handleSortByClick}
                      >
                        Sort By: {sortByLabel}
                      </Button>
                      <Menu
                        id="simple-menu"
                        anchorEl={sortByAnchorEl}
                        keepMounted
                        open={sortByAnchorEl}
                        onClose={() => this.setState({ sortByAnchorEl: null })}
                      >
                        <MenuItem onClick={() => sortByScanDate()}>
                          <ListItemIcon>
                            <ScannerIcon fontSize="small" />
                          </ListItemIcon>
                          Scan Date
                        </MenuItem>
                        <MenuItem onClick={() => sortByUploadDate()}>
                          <ListItemIcon>
                            <PublishIcon fontSize="small" />
                          </ListItemIcon>
                          Upload Date
                        </MenuItem>
                      </Menu>
                    </div>
                  }
                />
                <List style={{ maxHeight: "100%", overflow: "auto" }}>
                  {!loadingScans ? (

                    renderScans.map((scan, i) => {

                      let NoResults = false;
                      let Invalid = false;

                      if (scan.status === 'noRecords') {
                        NoResults = true;
                      }

                      if (scan.status === 'invalid') {
                        Invalid = true;
                      }
                      return (
                        <ListItem
                          key={scan.id}
                          className={["scansListItem", NoResults ? "NoResults" : (Invalid ? "Invalid" : "")]}
                        >
                          <ListItemText primary={scan.scan_name}
                            onMouseEnter={(e) => handlePopoverOpen(e, scan.id)}
                            onMouseLeave={() => handlePopoverClose()}
                            style={{ maxWidth: "30%" }}
                          />
                          <ListItemSecondaryAction>
                            <IconButton
                              edge="end"
                              onClick={(e) => handleScanClick(e, scan.id)}
                            >
                              <MoreVertIcon />
                            </IconButton>
                            <Menu
                              id={"vulnerability-simple-menu-" + scan.id}
                              anchorEl={this.state.vulnerabilityAnchorEl}
                              open={openScanMenu === scan.id}
                              onClose={() => {
                                this.setState({ vulnerabilityAnchorEl: null, openScanMenu: null })
                              }}
                            >
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "Edit Scan",
                                    scan: scan,
                                  })
                                }
                              >
                                <ListItemIcon><EditIcon fontSize="small" /></ListItemIcon>
                                Edit Scan
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "New Analysis",
                                    id: scan.id,
                                    isScan: true,
                                    client: client_ID,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <AddIcon fontSize="small" />
                                </ListItemIcon>
                                New Analysis
                              </MenuItem>
                              <MenuItem
                                onClick={(e) => handleDeleteScan(e, scan.id)}
                              >
                                <ListItemIcon>
                                  <DeleteIcon fontSize="small" />
                                </ListItemIcon>
                                Delete
                              </MenuItem>
                            </Menu>
                          </ListItemSecondaryAction>
                          <Popover
                            id="mouse-over-popover"
                            className={classes.popover}
                            classes={{ paper: classes.paper }}
                            style={{ pointerEvents: 'none' }}
                            open={openedPopoverId === scan.id}
                            anchorEl={popoverAnchorEl}

                            anchorOrigin={{
                              vertical: 'bottom',
                              horizontal: 'left',
                            }}
                            transformOrigin={{
                              vertical: 'top',
                              horizontal: 'left',
                            }}
                            onClose={handlePopoverClose}
                            disableRestoreFocus
                          >
                            <Box className={classes.popoverContainer}>
                              <Grid container rowSpacing={1} columnSpacing={{ xs: 1, sm: 2, md: 3 }}>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" component="div" className={classes.popoverHeader}>
                                    Report Name
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.report_name}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Policy Name
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.policy_name}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Scan Date
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.report_date}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Uploaded
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.upload_date}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Total Vulnerabilities
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.total_cve}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Unique Vulnerabilities
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.unique_cve}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Total Records
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.record_count_total}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    With vulnerabilities
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.vulnerability_count}
                                    {scan.record_count_total > 0 &&
                                      ` (${percentage(
                                        scan.vulnerability_count,
                                        scan.record_count_total
                                      )}%)`}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Total Hosts
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.host_count_total}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    With vulnerabilities
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.host_count}
                                    {scan.host_count_total > 0 &&
                                      ` (${percentage(scan.host_count, scan.host_count_total)}%)`}
                                  </Typography>
                                </Grid>
                                <Grid item xs={6} className={classes.popoverItems}>
                                  <Typography gutterBottom variant="body2" className={classes.popoverHeader} component="div">
                                    Cyio Analysis
                                  </Typography>
                                  <Typography component="div" variant="h5">
                                    {scan.analysis_count}
                                  </Typography>
                                </Grid>
                              </Grid>
                            </Box>
                          </Popover>
                        </ListItem>

                      );
                    })
                  ) : (
                    <ListItem className="card-body bg-secondary">
                      No Scans
                    </ListItem>
                  )}
                </List>
              </CardContent>
              <CardActions style={{ justifyContent: "center" }}>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<CloudUploadIcon />}
                  onClick={() =>
                    handleDialogOpen({ modal: "Vulnerability Scan" })
                  }
                >
                  Upload a Vulnerability Scan
                </Button>
              </CardActions>
            </Paper>
          </Grid>
        </Grid>
        {
          pendingAnalysis && (
            <Chip
              size="small"
              style={{ height: '17px', fontSize: '0.9em', marginBottom: '10px', textAlign: 'center' }}
              label={`Pending Analysis: ${pendingAnalysis}`}
            />
          )
        }
        <Typography variant="h4" gutterBottom={true}>
          Analyses
          {loadingAnalyses ? <LinearProgress /> : null}
        </Typography>
        <Grid container={true} spacing={3}>
          {!loadingAnalyses ? (
            analyses.map((analysis, i) => {
              return (
                <Grid item={true} md={6} lg={4} xl={3} style={{ minWidth: 425 }}>
                  <Paper
                    classes={{ root: classes.paper }}
                    elevation={2}
                    style={{ marginBottom: 20, height: 575 }}
                  >
                    <CardHeader
                      style={{ padding: 16 }}
                      action={
                        <div>
                          <IconButton
                            aria-label="settings"
                            onClick={(e) => handleAnalysisClick(e, analysis.id)}
                          >
                            <MoreVertIcon />
                          </IconButton>
                          {(scatterPlotData && scatterPlotData[analysis.id]) ? (
                            <Menu
                              id="simple-menu"
                              anchorEl={analysisAnchorEl}
                              open={openAnalysisMenu === analysis.id}
                              onClose={() =>
                                this.setState({ analysisAnchorEl: null, openAnalysisMenu: null })
                              }
                            >
                              <MenuItem
                                onClick={() => this.props.history.push(`/activities/vulnerability assessment/scans/explore results/${analysis.id}`)}
                              >
                                <ListItemIcon>
                                  <ExploreIcon fontSize="small" />
                                </ListItemIcon>
                                Explore Results
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleLinkClink('/activities/vulnerability assessment/scans/view charts',
                                    {
                                      analysis_id: analysis.id,
                                      analyses,
                                    })
                                }
                              >
                                <ListItemIcon>
                                  <ShowChartIcon fontSize="small" />
                                </ListItemIcon>
                                View Charts
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleLinkClink('/activities/vulnerability assessment/scans/compare analysis',
                                    {
                                      analyses,
                                      scatterPlotData: scatterPlotData
                                    }
                                  )}
                              >
                                <ListItemIcon>
                                  <CompareIcon fontSize="small" />
                                </ListItemIcon>
                                Compare
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "Generate Report",
                                    id: analysis.id,
                                    client: client_ID,
                                    scanName: analysis.scan.scan_name,
                                    success: false,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <DescriptionIcon fontSize="small" />
                                </ListItemIcon>
                                Generate Report
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "Export Data",
                                    id: analysis.id,
                                    client: client_ID,
                                    isLoading: false,
                                    success: false,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <ImportExportIcon fontSize="small" />
                                </ListItemIcon>
                                Export Data (CSV)
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "New Analysis",
                                    id: analysis.id,
                                    isScan: false,
                                    client: client_ID,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <AddIcon fontSize="small" />
                                </ListItemIcon>
                                New Analysis
                              </MenuItem>
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "Delete Data",
                                    id: analysis.id,
                                    client: client_ID,
                                    date: analysis.completed_date,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <DeleteIcon fontSize="small" />
                                </ListItemIcon>
                                Delete Analysis
                              </MenuItem>
                            </Menu>
                          ) : (
                            <Menu
                              id="simple-menu"
                              anchorEl={analysisAnchorEl}
                              open={openAnalysisMenu === analysis.id}
                              onClose={() =>
                                this.setState({ analysisAnchorEl: null, openAnalysisMenu: null })
                              }
                            >
                              <MenuItem
                                onClick={() =>
                                  handleDialogOpen({
                                    modal: "Delete Data",
                                    id: analysis.id,
                                    client: client_ID,
                                    date: analysis.completed_date,
                                  })
                                }
                              >
                                <ListItemIcon>
                                  <DeleteIcon fontSize="small" />
                                </ListItemIcon>
                                Delete Analysis
                              </MenuItem>
                            </Menu>
                          )
                          }
                        </div>
                      }
                      title={truncate(t(analysis.scan.scan_name), 30)}
                      subheader={moment(analysis.completed_date).fromNow()}
                    />
                    <CardContent
                      style={{
                        display: "flex", flexDirection: "column", alignItems: "center"
                      }}
                    >
                      <div style={{ width: 370, height: 370, marginRight: 20 }}>
                        <div className={analysisLoaderNoDisplay ? "AnalysisLoader" : "NoDisplay"}>
                          <CircularProgress />
                        </div>
                        {(scatterPlotData && scatterPlotData[analysis.id]) && (

                          <ResponsiveContainer
                            width="100%"
                            aspect={1}
                          >
                            <ScatterChart
                              margin={{
                                top: 0,
                                right: 0,
                                bottom: 20,
                                left: 0,
                              }}
                            >
                              <XAxis
                                type="number"
                                dataKey="x"
                                label={{
                                  value: "% of Hosts with Weakness",
                                  fill: 'white',
                                }}
                                domain={[0, 200]}
                                tick={false}
                              />
                              <YAxis
                                type="number"
                                dataKey="y"
                                label={{
                                  value: 'Weakness Score',
                                  angle: -90,
                                  fill: 'white',
                                }}
                                domain={[0, 200]}
                                tick={false}
                              />
                              <ZAxis range={[250]} />
                              <ReferenceLine x={0} stroke="white" />
                              <ReferenceLine y={0} stroke="white" />
                              <Tooltip
                                content={<CustomTooltip />}
                                cursor={false}
                              />
                              <Scatter
                                name={analysis.scan.scan_name}
                                data={scatterPlotData[analysis.id]}
                                fill="#49B8FC"
                              />
                            </ScatterChart>
                          </ResponsiveContainer>

                        )}
                      </div>
                      <div id={"chart-chips"}>
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
                      </div>
                    </CardContent>
                    {(scatterPlotData && scatterPlotData[analysis.id]) && (
                      <CardActions style={{ justifyContent: "right" }}>
                        <Button
                          disabled={loadingAnalyses}
                          variant="contained"
                          color="primary"
                          startIcon={<CloudUploadIcon />}
                          onClick={() => this.props.history.push(`/activities/vulnerability assessment/scans/explore results/${analysis.id}`)}
                        >
                          Explore Results
                        </Button>
                      </CardActions>
                    )}
                  </Paper>
                </Grid>
              );
            })
          ) : (
            <Grid item={true} xs={12}>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 350 }}
              >
                No analyses
              </Paper>
            </Grid>
          )}
          <Dialog
            open={openDialog}
            maxWidth="md"
          >
            <div>{dialogParams && renderDialogSwitch()}</div>
          </Dialog>
        </Grid>
      </div>
    );
  }
}

Scans.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  displayCreate: PropTypes.bool,
  onChangeOpenExports: PropTypes.func,
};

export default R.compose(inject18n, withRouter, withTheme, withStyles(styles))(Scans);
