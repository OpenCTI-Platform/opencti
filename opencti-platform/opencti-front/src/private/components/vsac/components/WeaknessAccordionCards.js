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

class WeaknessAccordionCards extends Component {
  constructor(props) {
    super(props);
    this.state = {
      weakness: this.props.weakness,
      selectedRow: this.props.selectedRow,
    };
  }

  componentWillReceiveProps(nextProps) {
    this.setState({ weakness: nextProps.weakness });
    this.setState({ selectedRow: nextProps.selectedRow });
  }

  render() {
    const { classes } = this.props;
    const { weakness, selectedRow } = this.state;

    const handleClick = (cwe_id, name) => {
      const params = {
        cwe_id: cwe_id,
      };

      this.props.action(params, name);
    };

    return (
      <Grid item={true} xs={12}>
        <Typography variant="h4" gutterBottom={true}>
          ...with weaknesses...
        </Typography>
        <Paper elevation={2} style={{ marginBottom: 20, minHeight: "300px" }}>
          <TableContainer style={{ maxHeight: 325 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rank</TableCell>
                  <TableCell>Weaknesses</TableCell>
                  <TableCell align="right">Count</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {weakness.length &&
                  weakness.map((item, i) => {
                    const rowName = "weaknessRow-" + i;

                    return (
                      <TableRow
                        key={rowName}
                        selected={rowName === selectedRow}
                        onClick={() => handleClick(item.cwe_id, rowName)}
                        hover
                        classes={{ root: classes.selectedTableRow }}
                      >
                        <TableCell component="th" scope="row">
                          {item.rank}
                        </TableCell>
                        <TableCell>{item.tooltip}</TableCell>
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

export default withStyles(styles)(WeaknessAccordionCards);
