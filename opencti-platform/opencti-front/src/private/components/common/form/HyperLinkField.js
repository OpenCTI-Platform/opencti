/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import * as R from 'ramda';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import InputAdornment from '@material-ui/core/InputAdornment';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import TextField from '@material-ui/core/TextField';
import { Edit } from '@material-ui/icons';
import Link from '@material-ui/core/Link';
import LaunchIcon from '@material-ui/icons/Launch';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions, Select, MenuItem, Input, InputLabel, FormControl } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import HyperLinks from '../../../../components/HyperLinks';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '85px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  inputTextField: {
    color: 'white',
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
  link: {
    textAlign: 'left',
    fontSize: '1rem',
    display: 'flex',
    minWidth: '50px',
    width: '100%',
  },
  launchIcon: {
    marginRight: '5%',
  },
  linkTitle: {
    color: '#fff',
    minWidth: 'fit-content',
  }
});

const hyperLinkFieldSoftwareAssetQuery = graphql`
  query HyperLinkFieldSoftwareQuery(
    $filters: [SoftwareAssetFiltering]
  ){
    softwareAssetList(
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          asset_type
          version
        }
      }
    }
  }
`;

const hyperLinkFieldHardwareAssetQuery = graphql`
  query HyperLinkFieldHardwareQuery(
    $filters: [HardwareAssetFiltering]
  ){
    hardwareAssetList(
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          asset_type
          version
        }
      }
    }
  }
`;

class HyperLinkField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      value: "",
      error: false,
      isSubmitting: true,
      data: this.props?.data ? [...this.props.data] : [],
      filteredData: [],
      softwareList: [],
      hardwareList: [],
      risksList: [],
      list: [],
    };
  }

  componentDidMount() {
    {
      this.props?.type === "hardware" &&
        fetchQuery(hyperLinkFieldHardwareAssetQuery, {
          filters: this.props.assetType
            ? [{ key: "asset_type", values: ["computing_device"] }]
            : [],
        })
          .toPromise()
          .then((data) => {
            const installedHardwareEntities = R.pipe(
              R.pathOr([], ["hardwareAssetList", "edges"]),
              R.map((n) => {
                return {
                  id: n.node.id,
                  name: n.node.name,
                };
              })
            )(data);
            this.setState({
              list: [...installedHardwareEntities],
            });
          });
    }

    {
      this.props.type === "software" &&
        fetchQuery(hyperLinkFieldSoftwareAssetQuery, {
          filters: this.props.assetType
            ? [{ key: "asset_type", values: [this.props.assetType] }]
            : [],
        })
          .toPromise()
          .then((data) => {
            const installedSoftwareEntities = R.pipe(
              R.pathOr([], ["softwareAssetList", "edges"]),
              R.map((n) => {
                const softwareName = R.concat(n.node.name, " ");
                const softwareNameWithVersion = R.concat(
                  softwareName,
                  n.node.version ? n.node.version : ""
                );
                return {
                  id: n.node.id,
                  name: softwareNameWithVersion,
                };
              }),
              R.sort(function (a, b) {
                return a.name.localeCompare(
                  b.name,
                  undefined,
                  {
                    numeric: true,
                    sensitivity: "base",
                  }
                );
              })
            )(data);
            this.setState({
              list: [...installedSoftwareEntities],
            });
          });
    }
  }

  handleAddAsset(list) {
    const addItem = R.find((n) => n.id === this.state.value)(list);
    this.setState({
      data: [...this.state.data, addItem],
      value: "",
      isSubmitting: false,
      // filteredData:[...this.state.filteredData, addItem.id]
    });
  }

  handleSubmit() {
    if (this.state.data.length === 0) {
      this.setState({ open: false });

      if (this.props.data !== this.state.date) {
        this.setState({ open: false }, () =>
          this.props.setFieldValue(this.props.name, [])
        );
      }
    } else {
      const finalOutput =
        this.state.data.length === 0
          ? []
          : this.state.data.map((item) => item.id);
      this.setState({ open: false }, () =>
        this.props.setFieldValue(this.props.name, finalOutput)
      );
    }
  }

  handleDelete(key) {
    this.setState(
      { data: this.state.data.filter((value, i) => i !== key) },
      () => {
        const finalOutput =
          this.state.data.length === 0
            ? []
            : this.state.data.map((item) => item.id);
        return this.props.setFieldValue(this.props.name, finalOutput);
      }
    );
  }

  handleDeleteItem(key) {
    this.setState({
      data: this.state.data.filter((value, i) => i !== key),
      value: "",
      isSubmitting: false,
    });
  }

  handleChange(event) {
    this.setState({ value: event.target.value });
  }

  render() {
    const {
      t,
      classes,
      name,
      history,
      title,
      helperText,
      containerstyle,
      style,
    } = this.props;
    const { error, data } = this.state;

    const installedOn =
      this.state.data.length > 0
        ? R.map((n) => ({ id: n.id, name: n.name }))(this.state.data)
        : [];
    return (
      <>
        <div style={{ display: "flex", alignItems: "center" }}>
          <Typography>{title && t(title)}</Typography>
          <div style={{ float: "left", margin: "5px 0 0 5px" }}>
            <Tooltip title={t(helperText)}>
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          {["installed_hardware", "installed_software"].includes(this.props.name) && (
            <IconButton
              size="small"
              onClick={() => this.setState({ open: true })}
            >
              <AddIcon />
            </IconButton>
          )}
        </div>
        <Field
          component={HyperLinks}
          name={name}
          fullWidth={true}
          disabled={true}
          multiline={true}
          rows="3"
          value={installedOn}
          className={classes.textField}
          InputProps={{
            className: classes.inputTextField,
          }}
          variant="outlined"
          history={history}
          handleDelete={this.handleDelete.bind(this)}
        />
        <Dialog open={this.state.open} fullWidth={true} maxWidth="sm">
          <DialogContent>{t(`Edit ${title}(s)`)}</DialogContent>
          <DialogContent
            style={{
              overflow: "hidden",
              display: "flex",
              alignItems: "center",
            }}
          >
            <div
              style={{
                overflow: "hidden",
                display: "flex",
                alignItems: "center",
                width: "100%",
                borderBottom: "1px #fff solid",
              }}
            >
              <FormControl style={{ width: "93%" }}>
                <InputLabel id="demo-simple-select-label">Assets</InputLabel>
                <Select
                  label={"Assets"}
                  labelId="demo-simple-select-label"
                  name={name}
                  fullWidth={true}
                  containerstyle={containerstyle}
                  // disabled={disabled || false}
                  // size={size}
                  style={style}
                  helperText={helperText}
                  value={this.state.value}
                  onChange={this.handleChange.bind(this)}
                  disableUnderline
                >
                  {this.state.list.length > 0 &&
                    this.state.list.map((data) => {
                      return (
                        data.name && (
                          <MenuItem key={data.id} value={data.id}>
                            {t(data.name)}
                          </MenuItem>
                        )
                      );
                    })}
                </Select>
              </FormControl>
              <IconButton
                aria-label="toggle password visibility"
                edge="end"
                onClick={this.handleAddAsset.bind(this, this.state.list)}
                style={{ marginTop: "20px" }}
                disabled={!this.state.value}
              >
                <AddIcon />
              </IconButton>
            </div>
          </DialogContent>
          <DialogContent>
            <div className={classes.scrollBg}>
              <div className={classes.scrollDiv}>
                <div className={classes.scrollObj}>
                  {installedOn.map((item, key) => (
                    <div
                      key={key}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                      }}
                    >
                      <Typography>{item.name}</Typography>
                      <IconButton
                        onClick={this.handleDeleteItem.bind(this, key)}
                      >
                        <Delete />
                      </IconButton>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant="outlined"
              onClick={() => this.setState({ open: false, value: "" })}
            >
              {t("Cancel")}
            </Button>
            <Button
              disabled={this.state.isSubmitting}
              variant="contained"
              onClick={this.handleSubmit.bind(this)}
              color="primary"
            >
              {t("Submit")}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

HyperLinkField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(HyperLinkField);
