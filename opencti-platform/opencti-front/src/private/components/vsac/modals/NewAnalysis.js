/* eslint-disable */
import React, { Component } from "react";
import Paper from "@material-ui/core/Paper";
import Grid from "@material-ui/core/Grid";
import Card from "@material-ui/core/Card";
import CardHeader from "@material-ui/core/CardHeader";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Button from "@material-ui/core/Button";
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import FormHelperText from '@material-ui/core/FormHelperText';
import FormGroup from '@material-ui/core/FormGroup';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select';
import { fetchVignettes } from "../../../../services/scan.service";
import {
  defaultVulnerabilityRange,
  defaultWeaknessCount,
  defaultVignette,
  vulnerabilityRanges,
  weaknessesCount,
} from "../data";

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

class NewAnalysis extends Component {
	constructor(props) {
		super(props);

		this.state = {
			scans: props.scans,
			id: props.id,
			client: props.client,
			vulnerabilityRanges: vulnerabilityRanges,
			weaknessesCount: weaknessesCount,
			vignettes: []
		}


	}

	componentDidMount() {
	    fetchVignettes(this.state.client)
	      .then((response) => {
	        const vignettes = response.data;
	        this.setState({ vignettes: vignettes });
	      })
	      .catch((error) => {
	        console.log(error);
	      });
  	}

	render() {

		const {
			scans,
			vulnerabilityRanges,
			weaknessesCount,
			vignettes,
		} = this.state;

		const handleScan = (event) => {
			this.setState({scan_id: event.target.value })
		}

		const handleVulnerability = (event) => {
			this.setState({vulnerability_range: event.target.value })
		}

		const handleWeaknessesCount = (event) => {

			this.setState({weakness_range: event.target.value })
		}

		const handleVignette = (event) => {
			this.setState({vignette: event.target.value })	
		}

		const handleSubmit = () => {

			const params = {
			    scan_id: this.state.scan_id,
			    vulnerability_range: this.state.vulnerability_range,
			    weakness_range: this.state.weakness_range,
			    vignette: this.state.vignette,
			  };

			this.props.action(this.state.id, this.state.client, params )
		}

		const handleClose = () => {
			this.props.onClose();
		};

		return (
			<Paper
				elevation={2}
				style={{ width: 400 }}
			>
				<Card>
					<CardHeader title="New Analysis" />
					<CardContent>
					<FormGroup row={true}>
						<FormControl className={classes.formControl} style={{width: '100%'}}>
					        <InputLabel id="demo-simple-select-label">Scan File</InputLabel>
					        <Select
					          labelId="demo-simple-select-label"
					          id="demo-simple-select"
					          onChange={(event) => handleScan(event)}
					        >
					        {
					        	scans.map((scan, i) => {
					        		return (
					          		<MenuItem value={scan.id}>{scan.scan_name}</MenuItem>
					          		)
					      		})
					         }
					        </Select>
					    </FormControl>
					    </FormGroup>
					    <FormGroup row={true}>
					    <FormControl className={classes.formControl} style={{width: '100%'}}>
					        <InputLabel id="demo-simple-select-label">Vulnerability Range</InputLabel>
					        <Select
					          labelId="demo-simple-select-label"
					          id="demo-simple-select"
					          onChange={(event) => handleVulnerability(event)}
					         
					        >
					          {
					        	vulnerabilityRanges.map((range, i) => {
					        		return (
					          		<MenuItem value={range.id}>{range.title}</MenuItem>
					          		)
					      		})
					         }
					        </Select>
					        <FormHelperText>Choose how many years of vulnerabilities to consider</FormHelperText>
					    </FormControl>
					    </FormGroup>
					    <FormGroup row={true}>
					    <FormControl className={classes.formControl} style={{width: '100%'}}>
					        <InputLabel id="demo-simple-select-label">Weakness Count</InputLabel>
					        <Select
					          labelId="demo-simple-select-label"
					          id="demo-simple-select"
					          onChange={(event) => handleWeaknessesCount(event)}
					         
					        >
					          {
					        	weaknessesCount.map((count, i) => {
					        		return (
					          		<MenuItem value={count.id}>{count.title}</MenuItem>
					          		)
					      		})
					         }
					        </Select>
					        <FormHelperText>The number of weaknesses to rank order</FormHelperText>
					    </FormControl>
					    </FormGroup>
					    <FormGroup row={true}>
						<FormControl className={classes.formControl} style={{width: '100%'}}>
					        <InputLabel id="demo-simple-select-label">Influence Weakness Scores with Vignette</InputLabel>
					        <Select
					          labelId="demo-simple-select-label"
					          id="demo-simple-select"
					          onChange={(event) => handleVignette(event)}
					         
					        >
					        { vignettes.length > 0 && (
					        	vignettes.map((vignette, i) => {
					        		return (
					          		<MenuItem value={vignette.name}>{vignette.name}</MenuItem>
					          		)
					      		}))
					         }
					          
					        </Select>
					        <FormHelperText>The number of weaknesses to rank order</FormHelperText>
					    </FormControl>					    
					    </FormGroup>
					</CardContent>
					<CardActions style={{ justifyContent: "right" }}>
						<Button
							size="small"
							color="secondary"
							onClick={handleClose}
						>
							Cancel
						</Button>
						<Button
						 	size="small"
							color="primary"
							onClick={handleSubmit}
						>
							Submit
						</Button>
					</CardActions>
				</Card>
			</Paper>
		);
	}
}

export default NewAnalysis;
