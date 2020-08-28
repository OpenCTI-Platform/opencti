import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { SettingsInputComponent } from '@material-ui/icons';
import Grid from '@material-ui/core/Grid';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';
import Loader from '../../../../components/Loader';
import { itemColor } from '../../../../utils/Colors';

const styles = () => ({
  paper: {
    minHeight: 300,
    maxHeight: 300,
    height: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  labelsCloud: {
    width: '100%',
    height: 300,
  },
  label: {
    width: '100%',
    height: 100,
    padding: 15,
  },
  labelNumber: {
    fontSize: 30,
    fontWeight: 500,
  },
  labelValue: {
    fontSize: 15,
  },
});

const stixCoreObjectStixCoreRelationshipsCloudDistributionQuery = graphql`
  query StixCoreObjectStixCoreRelationshipsCloudDistributionQuery(
    $fromId: String!
    $toTypes: [String]
    $relationship_type: String
    $inferred: Boolean
    $startDate: DateTime
    $endDate: DateTime
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
      inferred: $inferred
      startDate: $startDate
      endDate: $endDate
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
    }
  }
`;

class StixCoreObjectStixCoreRelationshipsCloud extends Component {
  hexToRGB(hex, transp = 0.1) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgb(${r}, ${g}, ${b}, ${transp})`;
  }

  renderContent() {
    const {
      t,
      n,
      stixCoreObjectId,
      stixCoreObjectType,
      relationshipType,
      field,
      inferred,
      startDate,
      endDate,
      classes,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromId: stixCoreObjectId,
      toTypes: stixCoreObjectType ? [stixCoreObjectType] : null,
      inferred: inferred || false,
      startDate: startDate || null,
      endDate: endDate || null,
      relationship_type: relationshipType,
      field,
      operation: 'count',
      limit: 9,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectStixCoreRelationshipsCloudDistributionQuery}
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            return (
              <div className={classes.labelsCloud}>
                <Grid container={true} spacing={0}>
                  {props.stixCoreRelationshipsDistribution.map((line) => {
                    const color = itemColor(line.label);
                    return (
                      <Grid
                        key={line.label}
                        item={true}
                        xs={4}
                        style={{ padding: 0 }}
                      >
                        <div
                          className={classes.label}
                          style={{
                            color,
                            borderColor: color,
                            backgroundColor: this.hexToRGB(color),
                          }}
                        >
                          <div className={classes.labelNumber}>
                            {n(line.value)}
                          </div>
                          <div className={classes.labelValue}>
                            {t(`entity_${line.label}`)}
                          </div>
                        </div>
                      </Grid>
                    );
                  })}
                </Grid>
              </div>
            );
          }
          if (props) {
            return (
              <div
                style={{
                  display: 'table',
                  height: '100%',
                  width: '100%',
                }}
              >
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }

  render() {
    const {
      t,
      classes,
      variant,
      title,
      entityType,
      configuration,
      handleOpenConfig,
    } = this.props;
    if (variant === 'explore') {
      return (
        <Paper classes={{ root: classes.paperExplore }} elevation={2}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left', padding: '10px 0 0 10px' }}
          >
            {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
          </Typography>
          <Security needs={[EXPLORE_EXUPDATE]}>
            <IconButton
              color="secondary"
              aria-label="Update"
              size="small"
              classes={{ root: classes.updateButton }}
              onClick={handleOpenConfig.bind(this, configuration)}
            >
              <SettingsInputComponent fontSize="inherit" />
            </IconButton>
          </Security>
          <div className="clearfix" />
          {this.renderContent()}
        </Paper>
      );
    }
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {this.renderContent()}
        </Paper>
      </div>
    );
  }
}

StixCoreObjectStixCoreRelationshipsCloud.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  stixCoreObjectId: PropTypes.string,
  relationshipType: PropTypes.string,
  stixCoreObjectType: PropTypes.string,
  inferred: PropTypes.bool,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectStixCoreRelationshipsCloud);
