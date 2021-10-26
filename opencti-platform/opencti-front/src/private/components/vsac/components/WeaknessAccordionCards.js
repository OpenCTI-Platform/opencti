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
import { makeStyles } from "@material-ui/core/styles";
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
import BugReportIcon from '@material-ui/icons/BugReport';

class WeaknessAccordionCards extends Component {
  constructor(props) {
    super(props);
  }

  render() {
    return (
      <Grid item={true} xs={12}>
        <Typography variant="h4" gutterBottom={true}>
          ...with weaknesses...
        </Typography>
        <Paper elevation={2} style={{ marginBottom: 20 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rank</TableCell>
                  <TableCell>Products</TableCell>
                  <TableCell align="right">Count</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell component="th" scope="row">
                    2
                  </TableCell>
                  <TableCell>Inadequate Encryption Strength</TableCell>
                  <TableCell align="right">4</TableCell>
                </TableRow>

                <TableRow>
                  <TableCell component="th" scope="row">
                    3
                  </TableCell>
                  <TableCell>Use of a Broken or Risky Cryptographic Algorithm</TableCell>
                  <TableCell align="right">4</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Grid>
    );
  }
}

export default WeaknessAccordionCards;
