/* eslint-disable */
import React, { Component } from "react";
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

class Products extends Component {
  constructor(props) {
    super(props);
    this.state = {
      software: this.props.software,
      selectedRow: this.props.selectedRow,
    };
  }

  componentWillReceiveProps(nextProps) {
    this.setState({ software: nextProps.software });
    this.setState({ selectedRow: nextProps.selectedRow });
  }

  render() {
    const { classes } = this.props;
    const { software, selectedRow } = this.state;

    const handleClick = (cpe_id, name) => {
      const params = {
        cpe_id: cpe_id,
      };

      this.props.action(params, name, 'software');
    };

    return (
      <Grid item={true} xs={12}>
        <Typography variant="h4" gutterBottom={true}>
        ...With products...
        </Typography>
        <Paper elevation={2} style={{ marginBottom: 20, minHeight: "300px" }}>
          <TableContainer style={{ maxHeight: 325 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rank</TableCell>
                  <TableCell>Products</TableCell>
                  <TableCell align="right">Count</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {software.length &&
                  software.map((item, i) => {
                    const rowName = "productRow-" + i;
                    return (
                      <TableRow
                        key={rowName}
                        selected={rowName === selectedRow}
                        onClick={() => handleClick(item.cpe_id, rowName)}
                        hover
                        classes={{ root: classes.selectedTableRow }}
                      >
                        <TableCell component="th" scope="row">
                          {item.rank}
                        </TableCell>
                        <TableCell>{item.cpe_id}</TableCell>
                        <TableCell align="right">{item.record_count}</TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Grid>
    );
  }
}

export default withStyles(styles)(Products);
