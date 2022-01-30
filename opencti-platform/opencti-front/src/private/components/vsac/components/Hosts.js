/* eslint-disable */
import React, { Component } from "react";
import CircularProgress from "@material-ui/core/CircularProgress";
import Grid from "@material-ui/core/Grid";
import Paper from "@material-ui/core/Paper";
import Typography from "@material-ui/core/Typography";
import { withStyles } from "@material-ui/core/styles";
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

      this.props.action(params, name, 'host');
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
