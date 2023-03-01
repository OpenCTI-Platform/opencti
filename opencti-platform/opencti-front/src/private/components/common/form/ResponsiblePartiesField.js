/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import {
    compose,
    map,
    pipe,
    pathOr,
    filter,
    uniq,
  } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import Delete from '@material-ui/icons/Delete';
import InputAdornment from '@material-ui/core/InputAdornment';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import InsertLinkIcon from '@material-ui/icons/InsertLink';
import LinkOffIcon from '@material-ui/icons/LinkOff';
import graphql from 'babel-plugin-relay/macro';
import TextField from '@material-ui/core/TextField';
import { Edit } from '@material-ui/icons';
import Link from '@material-ui/core/Link';
import LaunchIcon from '@material-ui/icons/Launch';
import Autocomplete from '@material-ui/lab/Autocomplete';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions, Select, MenuItem, Input, InputLabel, FormControl } from '@material-ui/core';
import NewTextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { commitMutation, fetchQuery } from '../../../../relay/environment';


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
    descriptionBox: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
    },
    inputTextField: {
      color: 'white',
    },
    textField: {
      background: theme.palette.header.background,
    },
    dialogAction: {
      margin: '15px 20px 15px 0',
    },
  });

const responsiblePartiesFieldQuery = graphql`
  query ResponsiblePartiesFieldQuery(
    $orderedBy: OscalResponsiblePartyOrdering
    $orderMode: OrderingMode
  ){
    oscalResponsibleParties(
      orderedBy: $orderedBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          created
          name
        }
      }
    }
  }
`;

const responsiblePartiesFieldAddMutation = graphql`
  mutation ResponsiblePartiesFieldAddMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

const responsiblePartiesFieldRemoveMutation = graphql`
  mutation ResponsiblePartiesFieldRemoveMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    removeReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

class ResponsiblePartiesField extends Component {
  constructor(props) {
    super(props);
    this.state = {
        open: false,
        error: false,
        parties: [],
        currentParties: this.props.data ? [...this.props.data] : [],
        party: null,
    };
  }

  componentDidMount() {
    fetchQuery(responsiblePartiesFieldQuery, {
        orderedBy: 'name',
        orderMode: 'asc',
      })
        .toPromise()
        .then((data) => {
          const transformLabels = pipe(
            pathOr([], ['oscalResponsibleParties', 'edges']),
            map((n) => ({
              label: n.node.name,
              value: n.node.id,
            })),
          )(data);
          this.setState({ parties: [...transformLabels] });
        });
  }

  handleAdd() {
    this.setState({
        currentParties: uniq([...this.state.currentParties, this.state.party]),
        open: false,
    });

    commitMutation({
        mutation: responsiblePartiesFieldAddMutation,
        variables: {
          toId: this.state.party?.value,
          fromId: this.props.id,
          fieldName: 'responsible_parties',
          from_type: this.props.fromType,
          to_type: this.props.toType,
        },
      })
  }

  handleDelete(key) {
    const newParties = this.state.currentParties.filter((item, index) => index !== key)
    this.setState({
        currentParties: newParties,
    });

    commitMutation({
        mutation: responsiblePartiesFieldRemoveMutation,
        variables: {
          toId: this.state.party?.value,
          fromId: this.props.id,
          fieldName: 'responsible_parties',
          from_type: this.props.fromType,
          to_type: this.props.toType,
        },
        onCompleted: () => {
            this.setState({
                open: false
            });
        },
      })
  }

//   handleSubmit() {
//     if (this.state.data.length === 0) {
//       this.setState({ open: false });

//       if (this.props.data !== this.state.date) {
//         this.setState({ open: false }, () =>
//           this.props.setFieldValue(this.props.name, [])
//         );
//       }
//     } else {
//       const finalOutput =
//         this.state.data.length === 0
//           ? []
//           : this.state.data.map((item) => item.id);
//       this.setState({ open: false }, () =>
//         this.props.setFieldValue(this.props.name, finalOutput)
//       );
//     }
//   }

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

    return (
      <>
        <div style={{ display: "flex", alignItems: "center" }}>
          <Typography>{title && t(title)}</Typography>
          <div style={{ float: "left", margin: "5px 0 0 5px" }}>
            <Tooltip title={t("Baseline Configuration Name")}>
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          <IconButton
            size="small"
            onClick={() => this.setState({ open: true })}
          >
            <InsertLinkIcon />
          </IconButton>
        </div>
        <div className={classes.scrollBg}>
          <div className={classes.scrollDiv}>
            <div className={classes.scrollObj}>
              {this.state.currentParties &&
                this.state.currentParties.map((party, key) => (
                  <div key={key} className={classes.descriptionBox}>
                    <Typography>{party && t(party?.label)}</Typography>
                    <IconButton
                      size="small"
                      onClick={this.handleDelete.bind(this, key)}
                    >
                      <LinkOffIcon />
                    </IconButton>
                  </div>
                ))}
            </div>
          </div>
        </div>
        <Dialog open={this.state.open} fullWidth={true} maxWidth="sm">
          <DialogContent>{title && t(title)}</DialogContent>
          <DialogContent style={{ overflow: "hidden" }}>
            <Autocomplete
              size="small"
              loading={this.state.party || false}
              loadingText="Searching..."
              className={classes.autocomplete}
              classes={{
                popupIndicatorOpen: classes.popupIndicator,
              }}
              noOptionsText={t("No available options")}
              options={this.state.parties}
              getOptionLabel={(option) =>
                option.label ? option.label : option
              }
              onChange={(event, value) => this.setState({ party: value })}
              selectOnFocus={true}
              autoHighlight={true}
              renderInput={(params) => (
                <TextField
                  variant="outlined"
                  {...params}
                  label="Responsible Parties"
                />
              )}
            />
          </DialogContent>
          <DialogActions className={classes.dialogAction}>
            <Button
              variant="outlined"
              onClick={() => this.setState({ open: false, party: null })}
            >
              {t("Cancel")}
            </Button>
            <Button
              variant="contained"
              onClick={this.handleAdd.bind(this)}
              color="primary"
              disabled={this.state.party === null}
            >
              {t("Add")}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

ResponsiblePartiesField.propTypes = {
  name: PropTypes.string,
  device: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(ResponsiblePartiesField);
