/* eslint-disable */
import React, { Component } from "react";
import Paper from "@material-ui/core/Paper";
import Grid from "@material-ui/core/Grid";
import Card from "@material-ui/core/Card";
import CardHeader from "@material-ui/core/CardHeader";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Button from "@material-ui/core/Button";
import InputLabel from "@material-ui/core/InputLabel";
import TextField from "@material-ui/core/TextField";
import MenuItem from "@material-ui/core/MenuItem";
import FormLabel from "@material-ui/core/FormLabel";
import FormControl from "@material-ui/core/FormControl";
import FormGroup from "@material-ui/core/FormGroup";
import FormControlLabel from "@material-ui/core/FormControlLabel";
import FormHelperText from "@material-ui/core/FormHelperText";
import Switch from "@material-ui/core/Switch";
import Select from "@material-ui/core/Select";
import List from "@material-ui/core/List";
import ListItem from "@material-ui/core/ListItem";
import ListItemIcon from "@material-ui/core/ListItemIcon";
import ListItemSecondaryAction from "@material-ui/core/ListItemSecondaryAction";
import ListItemText from "@material-ui/core/ListItemText";
import DialogTitle from "@material-ui/core/DialogTitle";
import Dialog from "@material-ui/core/Dialog";
import DialogActions from "@material-ui/core/DialogActions";
import Checkbox from "@material-ui/core/Checkbox";
import { fetchTrendableAnalyses } from "../../../../services/analysis.service";
import CircularProgress from "@material-ui/core/CircularProgress";

const classes = {
	root: {
		flexGrow: 1,
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
};

class GenerateReport extends Component {
	constructor(props) {
		super(props);

		this.state = {
			report_title: this.props.scanName,
			includeAppendices: true,
			includeBenchmarkComparison: true,
			includeCharts: true,
			includeMostVulnerableHosts: true,
			includeMostVulnerableProducts: true,
			includeTOC: true,
			includeTitle: true,
			includeTrendingComparison: true,
			includeVulnerabilitiesByServerity: true,
			topN: 5,
			analysisToTrend: [],
			analysis_id: this.props.id,
			client: this.props.client,
			open: false,
			analysisToTrend: [],
			checkedAnalysesToTrend: [],
			success: this.props.success
		};
	}

	componentWillReceiveProps(nextProps) {
    	this.setState({ success: nextProps.success });
   		this.forceUpdate();
  	}

	render() {
		const {
			report_title,
			includeAppendices,
			includeBenchmarkComparison,
			includeCharts,
			includeMostVulnerableHosts,
			includeMostVulnerableProducts,
			includeTOC,
			includeTitle,
			includeTrendingComparison,
			includeVulnerabilitiesByServerity,
			topN,
			analysisToTrend,
			checkedAnalysesToTrend,
			analysis_id,
			client,
			open,
			success,
		} = this.state;

		const handleFormChange = (prop, event) => {
			this.setState({ [prop]: event.target.value });

			console.log(this.state);
		};
		const handleCheckChange = (prop, event) => {
			this.setState({ [prop]: event.target.checked });
		};

		const handleDialogOpen = () => {
			this.setState({ open: true });
			getTrendableAnalysis(analysis_id, client)

		};

		const handleClose = () => {
			this.setState({ open: false });
		};

		const handleGenerateReportClose = () => {
			this.props.onClose();
		}

		const getTrendableAnalysis = (id, client) => {
			console.log(1)
			fetchTrendableAnalyses(id, client)
				.then((response) => {
					this.setState({ analysisToTrend: response.data });
				})
				.catch((error) => {
					console.log(error);
				});
		};

		const handleAnalysesToTrend = (event) => {
			event.preventDefault();

			if (event.target.checked) {

				this.state.checkedAnalysesToTrend.push(event.target.value)

				this.setState({checkedAnalysesToTrend: checkedAnalysesToTrend })
			} else {
				const array = checkedAnalysesToTrend;
				const index = array.indexOf(event.target.value);
				this.setState({checkedAnalysesToTrend: array.splice(index, 1)});
			}
		};

		const handleSubmit = (event) => {
			
			const params = {
		      title: report_title,
		      include_title: includeTitle,
		      toc: includeTOC,
		      benchmark_comparison: includeBenchmarkComparison,
		      trending_comparison: includeTrendingComparison,
		      analyses_to_trend: checkedAnalysesToTrend,
		      most_vulnerable_hosts: includeMostVulnerableHosts,
		      most_vulnerable_products: includeMostVulnerableProducts,
		      vulnerabilities_by_severity: includeVulnerabilitiesByServerity,
		      scoring_method: "tbc",
		      charts: includeCharts,
		      appendices: includeAppendices,
		      top_n: Number(topN),
		    };

			this.props.action(analysis_id, client, params);
			event.preventDefault()
		}

		return (
			<Paper
				
				elevation={2}
				style={{ width: 680 }}
			>
				<Card>
					<CardHeader title="Create Vulnerability Assessment Report" />
					{ success ?
					<CardContent>
						<p>An e-mail will be sent to your address with a download link when the report is ready.</p>
					</CardContent>
					:
					<CardContent>
						<p>
							This feature will generate a report in Markdown (a
							lightweight text markup language) that can be
							further edited and then transformed into the output
							of your choice (Word, PDF, etc.). For more about
							Markdown and useful conversion tools, see{" "}
							<a
								href="https://www.markdownguide.org"
								target="_blank"
								rel="noopener noreferrer"
							>
								https://www.markdownguide.org
							</a>
						</p>
						<FormGroup row={true}>
							<TextField
								style={{ width: "100%" }}
								label="Report Title"
								defaultValue={`${report_title} Assessment Report`}
								value={report_title}
								onChange={(event) =>
									handleFormChange("report_title", event)
								}
							/>
						</FormGroup>
						<FormGroup row={true}>
							<List >
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="includeTitle"
											checked={includeTitle}
											onChange={(event) =>
												handleCheckChange(
													"includeTitle",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Include Title in Report"}
										secondary={
											"The report title from this form will be printed as a heading at the top of the report document."
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="includeTOC"
											checked={includeTOC}
											onChange={(event) =>
												handleCheckChange(
													"includeTOC",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Include Table of Contents"}
										secondary={
											"A Table of Contents with section headings."
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="includeBenchmarkComparison"
											checked={includeBenchmarkComparison}
											onChange={(event) =>
												handleCheckChange(
													"includeBenchmarkComparison",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Include Industry Benchmarks"}
										secondary={
											"CWE Top 25 Weaknesses Comparison."
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											checked={includeBenchmarkComparison}
											onChange={(event) =>
												handleCheckChange(
													"includeBenchmarkComparison",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={
											"Include Trending Comparison Chart"
										}
										secondary={
											"Line chart showing historical trends of vulnerabilities and other metadata from your previous analyses."
										}
									/>
								</ListItem>
								<ListItem>
									<ListItemSecondaryAction>
										<Button
											color="primary"
											onClick={handleDialogOpen}
										>
											Choose Previous Analyses
										</Button>
									</ListItemSecondaryAction>
								</ListItem>
							</List>
							<Dialog
								onClose={handleClose}
								aria-labelledby="simple-dialog-title"
								open={open}
							>
								<DialogTitle id="simple-dialog-title">
									Choose Previous Analyses
								</DialogTitle>
								<List >
									{analysisToTrend.length ? (
										analysisToTrend.map((scan) => {
											let checked = null;
											if(checkedAnalysesToTrend.includes(scan.analysis_id)){
												 checked = true;
											} else {
												 checked = false;
											}

											return (
												<ListItem dense button>
													<ListItemIcon>
														<Checkbox
															checked={checked}
															edge="start"
															tabIndex={-1}
															disableRipple
															inputProps={{
																"aria-label":
																	scan.scan_name,
															}}
															value={
																scan.analysis_id
															}
															onChange={(
																event
															): void => {
																handleAnalysesToTrend(
																	event
																);
															}}
														/>
													</ListItemIcon>
													<ListItemText
														primary={scan.scan_name}
													/>
												</ListItem>
											);
										})
									) : (
										<div
											style={{
												alignItems: "center",
												display: "flex",
												justifyContent: "center",
											}}
										>
											<CircularProgress />
										</div>
									)}
								</List>
								<DialogActions>
									<Button
										onClick={handleClose}
										color="primary"
									>
										Close
									</Button>
								</DialogActions>
							</Dialog>
						</FormGroup>
						<FormGroup row={true}>
							<List >
								<ListItem dense button>
									<ListItemIcon>
										<Select
											labelId="demo-simple-select-label"
											id="demo-simple-select"
											value={topN}
											onChange={(event) =>
												handleFormChange("topN", event)
											}
										>
											<MenuItem value={5}>5</MenuItem>
											<MenuItem value={10}>10</MenuItem>
											<MenuItem value={15}>15</MenuItem>
											<MenuItem value={20}>20</MenuItem>
											<MenuItem value={25}>25</MenuItem>
										</Select>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={
											"Number to use for the “Top N” tables"
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="checkedB"
											checked={includeMostVulnerableHosts}
											onChange={(event) =>
												handleCheckChange(
													"includeMostVulnerableHosts",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Top Vulnerable Hosts"}
										secondary={
											"A table listing the hosts with the highest-scoring vulnerabilities."
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="checkedB"
											checked={
												includeMostVulnerableProducts
											}
											onChange={(event) =>
												handleCheckChange(
													"includeMostVulnerableProducts",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Top Vulnerable Products"}
										secondary={
											"A table listing the software and hardware products with the highest-scoring vulnerabilities."
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="checkedB"
											checked={
												includeVulnerabilitiesByServerity
											}
											onChange={(event) =>
												handleCheckChange(
													"includeVulnerabilitiesByServerity",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={
											"Top Vulnerabilities by Severity"
										}
										secondary={
											"A table listing the highest-scoring vulnerabilities in each severity category (e.g. severe, high, etc.)"
										}
									/>
								</ListItem>
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="checkedB"
											checked={includeCharts}
											onChange={(event) =>
												handleCheckChange(
													"includeCharts",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={"Include Graphical Charts"}
										secondary={
											"SVG versions of charts to visualize the findings."
										}
									/>
								</ListItem>
							</List>
						</FormGroup>
						<FormGroup row={true}>
							<List >
								<ListItem dense button>
									<ListItemIcon>
										<Switch
											color="primary"
											name="checkedB"
											checked={includeAppendices}
											onChange={(event) =>
												handleCheckChange(
													"includeAppendices",
													event
												)
											}
										/>
									</ListItemIcon>
									<ListItemText
										style={{ width: "100%" }}
										primary={
											"Include Detailed Appendix Tables"
										}
										secondary={
											"The full listing of vulnerabilities per host and their solutions."
										}
									/>
								</ListItem>
							</List>
						</FormGroup>
					</CardContent>
					
					}
					<CardActions style={{ justifyContent: "right" }}>
						{ success ?
						<Button size="small" color="primary" onClick={handleGenerateReportClose}>
							Close
						</Button>
						:
						<div>
						<Button size="small" color="secondary" onClick={handleGenerateReportClose}>
							Cancel
						</Button>
						<Button size="small" color="primary" onClick={handleSubmit}>
							Submit
						</Button>
						</div>
						
						}	
					</CardActions>
				</Card>
			</Paper>
		);
	}
}

export default GenerateReport;
