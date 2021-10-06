/* eslint-disable */
import React, { Component } from "react";
import * as PropTypes from "prop-types";
import { withRouter, Link } from "react-router-dom";
import * as R from "ramda";
import { QueryRenderer } from "../../../relay/environment";
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from "../../../utils/ListParameters";
import ListLines from "../../../components/list_lines/ListLines";
import inject18n from "../../../components/i18n";
import ToolBar from "../data/ToolBar";
import { isUniqFilter } from "../common/lists/Filters";
import Security, { KNOWLEDGE_KNUPDATE } from "../../../utils/Security";
import NewAnalysis from "./modals/NewAnalysis";
import Delete from "./modals/Delete";
import ExportCSV from "./modals/ExportCSV";
import GenerateReport from "./modals/GenerateReport";
import VulnerabilityScan from "./modals/VulnerabilityScan";
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
import { fetchAllScans } from "../../../services/scan.service";
import { fetchAllAnalysis } from "../../../services/analysis.service";
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
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
} from "recharts";
import Chip from "@material-ui/core/Chip";

class Compare extends Component {
  constructor(props) {
    super(props);
  }

  render() {
    return (
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={4}>
          <Typography variant="h4" component="h2" gutterBottom>
            single_host_scan_tbkf3f.nessus
          </Typography>
          <Paper elevation={2} style={{ height: 350, marginBottom: 20 }}>
            <List>
              <ListItem
               dense
               button
              >
                    <ListItemIcon>
                      <Checkbox
                        edge="start"
                        checked={checked.indexOf(value) !== -1}
                        tabIndex={-1}
                        disableRipple
                        inputProps={{ "aria-labelledby": labelId }}
                      />
                    </ListItemIcon>
                    <ListItemText
                      id={labelId}
                      primary={`Line item ${value + 1}`}
                    />
                    <ListItemSecondaryAction>
                      <IconButton edge="end" aria-label="comments">
                        <CommentIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                );
              })}
            </List>
          </Paper>
        </Grid>
        <Grid item={true} xs={8}>
          <Paper
            elevation={2}
            style={{ height: 350, marginBottom: 20 }}
          ></Paper>
        </Grid>
      </Grid>
    );
  }
}

export default R.compose(inject18n, withRouter)(Compare);
