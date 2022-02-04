/* eslint-disable */
import { Component } from 'react';
import {Card, CardActions, ListItem, ListItemText, Paper} from '@material-ui/core';
import CardHeader from "@material-ui/core/CardHeader";
import CardContent from "@material-ui/core/CardContent";
import Typography from "@material-ui/core/Typography";
import List from "@material-ui/core/List";
import Button from "@material-ui/core/Button";
import {deleteAnalysis} from "../../../../services/analysis.service";
import {deleteScan} from "../../../../services/scan.service";

class DeleteScanVerify extends Component {
  constructor(props) {
    super(props);
    this.state = {
      clientId: props.clientId,
      scan: props.scan,
      analyses: props.analyses,
      onClose: props.onClose,
      onComplete: props.onComplete,
      handling: false
    };
  }

  render() {
    const {
      clientId,
      scan,
      analyses,
      onClose,
      onComplete
    } = this.state

    const handleDelete = async () => {
      this.setState({handling: true})
      for(const analysis of analyses) {
        await deleteAnalysis(analysis.id, clientId).catch((err) => console.log("Failed to delete analysis", err))
      }
      await deleteScan(scan.id, clientId).catch((err) => console.log(err))
      this.setState({handling: false})
      onComplete()
    }

    return (
      <Paper elevation={2} >
        <Card>
          <CardHeader title="Delete Scan with Analyses"/>
          <CardContent>
            <Typography
              variant={"h1"}
              noWrap={true}
              align="left"
            >
              { scan.scan_name }
            </Typography>
            <Typography sx={{fontSize: "0.9em"}}>
              To delete this scan, you will be required to delete the {analyses.length} associated {analyses.length === 1 ? "analysis" : "analyses"} with it:
            </Typography>
            <List dense style={{marginLeft: "10px"}}>
              {
                analyses.map((a) => {
                  return (
                    <ListItem
                      key={a.id}
                      disableGutters
                    >
                      <ListItemText primary={"- " + new Date(a.completed_date).toLocaleString()}/>
                    </ListItem>
                  )
                })
              }
            </List>
          </CardContent>
          <CardActions style={{justifyContent: "right"}}>
            <Button
              size="small"
              color="secondary"
              onClick={onClose}
              disabled={this.state.handling}
            >
              Cancel
            </Button>
            <Button
              size="small"
              color="primary"
              onClick={handleDelete}
              disabled={this.state.handling}
            >
              Delete All
            </Button>
          </CardActions>
        </Card>
      </Paper>
    );
  }
}

export default DeleteScanVerify;
