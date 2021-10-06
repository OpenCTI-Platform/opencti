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
import MenuItem from "@material-ui/core/MenuItem";
import FormHelperText from "@material-ui/core/FormHelperText";
import FormControl from "@material-ui/core/FormControl";
import Select from "@material-ui/core/Select";
import CircularProgress from '@material-ui/core/CircularProgress';

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

class ExportCSV extends Component {
	constructor(props) {
		super(props);
		console.log(props)
		this.state = {
			isloading: props.isLoading,
			success: props.success,
		}
	}

	handleClick = (event) => {
		this.props.action(this.props.id, this.props.client);
		event.preventDefault();
	};

	handleClose = () => {
		this.props.onClose();
	}

	componentWillReceiveProps(nextProps) {
    	this.setState({ isloading: nextProps.isLoading, success: nextProps.success });
   		this.forceUpdate();
  	}

  	renderMessage(success){

  		if(success){
  			return (<p>success</p>)
  		} else {
  			return (<p>A data table in CSV format will be compiled using the results of this analysis. When the file is ready, a link to it will be sent to your e-mail address.</p>)
  		}
  	}

	render() {
		return (
			<Paper
				classes={{ root: classes.paper }}
				elevation={2}
				style={{ width: "500px" }}
			>
				<Card>
					<CardHeader title="Export Analysis Results to CSV" />
					<CardContent>
					{ this.state.isloading 
						?  
							<div style={{ alignItems: "center", display: "flex", justifyContent: "center" }}>
								<CircularProgress />
							</div>
						:  this.renderMessage(this.state.success)
					}
					</CardContent>
					<CardActions style={{ justifyContent: "right" }}>
					{this.state.success
						?
						<div>
						<Button size="small" color="primary" onClick={this.handleClose}>
							Close
						</Button>
						</div>
						:
						<div>
						<Button size="small" color="secondary" onClick={this.handleClose}>
							Cancel
						</Button>
						<Button size="small" color="primary" onClick={this.handleClick}>
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

export default ExportCSV;
