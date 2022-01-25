/* eslint-disable */
import React, { Component } from "react";
import DescriptionIcon from "@material-ui/icons/Description";
import AddIcon from "@material-ui/icons/Add";
import EditOutlinedIcon from "@material-ui/icons/EditOutlined";
import ExploreIcon from "@material-ui/icons/Explore";
import ShowChartIcon from "@material-ui/icons/ShowChart";
import DeleteIcon from "@material-ui/icons/Delete";
import IconButton from "@material-ui/core/IconButton";
import CloudUploadIcon from "@material-ui/icons/CloudUpload";
import ArrowDropDownIcon from "@material-ui/icons/ArrowDropDown";
import ImportExportIcon from "@material-ui/icons/ImportExport";
import CompareIcon from "@material-ui/icons/Compare";
import ScannerIcon from "@material-ui/icons/Scanner";
import PublishIcon from "@material-ui/icons/Publish";
import Button from "@material-ui/core/Button";
import Card from "@material-ui/core/Card";
import CardHeader from "@material-ui/core/CardHeader";
import CardActions from "@material-ui/core/CardActions";
import CircularProgress from "@material-ui/core/CircularProgress";
import Grid from "@material-ui/core/Grid";
import Paper from "@material-ui/core/Paper";
import List from "@material-ui/core/List";
import ListItem from "@material-ui/core/ListItem";
import ListItemIcon from "@material-ui/core/ListItemIcon";
import ListItemText from "@material-ui/core/ListItemText";
import ListItemSecondaryAction from "@material-ui/core/ListItemSecondaryAction";
import Typography from "@material-ui/core/Typography";
import Tooltip from "@material-ui/core/Tooltip";
import CardContent from "@material-ui/core/CardContent";
import { DescriptionOutlined } from "@material-ui/icons";
import { withStyles } from "@material-ui/core/styles";
import MoreVertIcon from "@material-ui/icons/MoreVert";
import Menu from "@material-ui/core/Menu";
import MenuItem from "@material-ui/core/MenuItem";
import moment from "moment";
import Dialog from "@material-ui/core/Dialog";
import Table from "@material-ui/core/Table";
import TableBody from "@material-ui/core/TableBody";
import TableCell from "@material-ui/core/TableCell";
import TableContainer from "@material-ui/core/TableContainer";
import TableHead from "@material-ui/core/TableHead";
import TableRow from "@material-ui/core/TableRow";

const styles = (theme) => ({
  selectedTableRow: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: 'rgba(3, 45, 105)',
    },
  },
});

class Hosts extends Component {
  constructor(props) {
    super(props);

    this.state = {
      hosts: this.props.hosts,
      selectedRow: this.props.selectedRow,
    };
  }
  componentWillReceiveProps(nextProps) {
    this.setState({ hosts: nextProps.hosts });
    this.setState({ selectedRow: nextProps.selectedRow });
  }

  render() {
    const { classes } = this.props;
    const { hosts, selectedRow } = this.state;

    const handleClick = (host_ip, name) => {
      const params = {
        host_ip: host_ip,
      };

      this.props.action(params, name);
    };

    return (
      <Grid item={true} xs={12}>
        <Typography variant="h4" gutterBottom={true}>
          These hosts are susceptible to attack...
        </Typography>
        <Paper elevation={2} style={{ marginBottom: 20, minHeight: 300 }}>
          {hosts ? (
            <TableContainer style={{ maxHeight: 325 }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Rank</TableCell>
                    <TableCell>Host</TableCell>
                    <TableCell align="right">Count</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {hosts.length &&
                    hosts.map((host, i) => {
                      const rowName = "hostRow-" + i;

                      return (
                        <TableRow
                          key={rowName}
                          selected={rowName === selectedRow}
                          onClick={() => handleClick(host.host_ip, rowName)}
                          hover
                          classes={{ root: classes.selectedTableRow }}
                        >
                          <TableCell component="th" scope="row">
                            {host.rank}
                          </TableCell>
                          <TableCell>{host.host_ip}</TableCell>
                          <TableCell align="right">
                            {host.record_count}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <CircularProgress />
          )}
        </Paper>
      </Grid>
    );
  }
}

export default withStyles(styles)(Hosts);
