/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { parse } from '../../../../../utils/Time';
import { adaptFieldValue } from '../../../../../utils/String';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import ResponseType from '../../../common/form/ResponseType';
import RiskLifeCyclePhase from '../../../common/form/RiskLifeCyclePhase';
import Source from '../../../common/form/Source';
import { toastGenericError } from "../../../../../utils/bakedToast";
import DatePickerField from '../../../../../components/DatePickerField';
import TaskType from '../../../common/form/TaskType';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = (theme) => ({
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'auto',
    overflowX: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

class DataSourceDataUsageRestrictionsPopoverComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      close: false,
    };
  }

  handleCancelOpenClick() {
    this.setState({ close: true });
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  handleCloseMain() {
    this.setState({ close: false });
    this.props.handleCloseDataUsageRestrictions();
  }

  render() {
    const {
      t,
      classes,
      dataSource,
      refreshQuery,
    } = this.props;
    const { iep } = dataSource;
    return (
      <>
        <Dialog open={this.props.openDataUsageRestrictions} keepMounted={true}>
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t("Information Exchange Policy")}
          </DialogTitle>
          <DialogContent classes={{ root: classes.dialogContent }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={12}>
                <div style={{ marginBottom: "10px" }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: "left" }}
                  >
                    {t("ID")}
                  </Typography>
                  <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                    <Tooltip title={t("Name")}>
                      <Information fontSize="inherit" color="disabled" />
                    </Tooltip>
                  </div>
                  <div className="clearfix" />
                  {iep.id}
                </div>
              </Grid>
              <Grid xs={12} item={true}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Name")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Description")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {iep.name}
              </Grid>
              <Grid item={true} xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                  style={{ float: "left" }}
                >
                  {t("Description")}
                </Typography>
                <div style={{ float: "left", margin: "-1px 0 0 4px" }}>
                  <Tooltip title={t("Source")}>
                    <Information fontSize="inherit" color="disabled" />
                  </Tooltip>
                </div>
                <div className="clearfix" />
                {iep.description}
              </Grid>
              <Grid container item={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Start Date")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Start")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.start_date}
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("End Date")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("End")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.end_date}
                  </div>
                </Grid>
              </Grid>
              <Grid container item={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Encrypt In Transit")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Resource Type")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.encrypt_in_transit}
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Permitted Actions")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Resource Type")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.permitted_actions}
                  </div>
                </Grid>
              </Grid>
              <Grid container item={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Affected Party Notifications")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Resource Type")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.affected_party_notifications}
                  </div>
                </Grid>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("TLP")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Resource Type")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.tlp}
                  </div>
                </Grid>
              </Grid>
              <Grid container item={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <div style={{ marginBottom: "12px" }}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: "left" }}
                    >
                      {t("Unmodified Resale")}
                    </Typography>
                    <div style={{ float: "left", margin: "1px 0 0 5px" }}>
                      <Tooltip title={t("Resource Type")}>
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    {iep.unmodified_resale}
                  </div>
                </Grid>
                <Grid item={true} xs={12}>
                  <CyioCoreObjectExternalReferences
                    typename={iep.__typename}
                    externalReferences={iep?.external_references}
                    fieldName="external_references"
                    cyioCoreObjectId={iep?.id}
                    refreshQuery={refreshQuery}
                  />
                </Grid>
                <Grid item={true} xs={12}>
                  <CyioCoreObjectOrCyioCoreRelationshipNotes
                    typename={iep.__typename}
                    notes={iep.notes}
                    refreshQuery={refreshQuery}
                    fieldName="notes"
                    marginTop="20px"
                    cyioCoreObjectOrCyioCoreRelationshipId={
                      iep?.id
                    }
                  />
                </Grid>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions classes={{ root: classes.dialogClosebutton }}>
            <Button
              variant="outlined"
              onClick={this.handleCloseMain.bind(this)}
              classes={{ root: classes.buttonPopover }}
            >
              {t("Cancel")}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

DataSourceDataUsageRestrictionsPopoverComponent.propTypes = {
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
  dataSource: PropTypes.object,
  classes: PropTypes.object,
  openDataUsageRestrictions: PropTypes.bool,
  handleCloseDataUsageRestrictions: PropTypes.func,
};

const DataSourceDataUsageRestrictionsPopover = createFragmentContainer(
  DataSourceDataUsageRestrictionsPopoverComponent,
  {
    dataSource: graphql`
      fragment DataSourceDataUsageRestrictionsPopover_dataSource on DataSource {
        iep {
          id
          name
          tlp
          color
          created
          modified
          end_date
          start_date
          description
          attribution
          iep_version
          entity_type
          definition_type
          permitted_actions
          unmodified_resale
          encrypt_in_transit
          affected_party_notifications
          external_references {
            __typename
            id
            source_name
            description
            entity_type
            url
            hashes {
              value
            }
            external_id
          }
          notes {
            __typename
            id
            entity_type
            abstract
            content
            authors
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(DataSourceDataUsageRestrictionsPopover);