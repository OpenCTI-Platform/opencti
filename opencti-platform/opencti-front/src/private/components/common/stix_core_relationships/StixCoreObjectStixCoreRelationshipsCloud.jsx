import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { SettingsInputComponent } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import Loader from '../../../../components/Loader';
import { hexToRGB, itemColor } from '../../../../utils/Colors';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

const styles = (theme) => ({
  paper: {
    minHeight: 300,
    maxHeight: 300,
    height: 300,
    marginTop: theme.spacing(1),
    padding: 0,
    borderRadius: 4,
    overflow: 'hidden',
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
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $relationship_type: [String]
    $startDate: DateTime
    $endDate: DateTime
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      relationship_type: $relationship_type
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
  renderContent() {
    const {
      t,
      n,
      stixCoreObjectId,
      stixCoreObjectType,
      relationshipType,
      field,
      startDate,
      endDate,
      classes,
      isTo,
      noDirection,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromOrToId: noDirection ? stixCoreObjectId : null,
      elementWithTargetTypes:
        noDirection && stixCoreObjectType ? [stixCoreObjectType] : null,
      fromId: !isTo && !noDirection ? stixCoreObjectId : null,
      toId: isTo && !noDirection ? stixCoreObjectId : null,
      relationship_type: relationshipType,
      toTypes:
        !isTo && !noDirection && stixCoreObjectType
          ? [stixCoreObjectType]
          : null,
      fromTypes:
        isTo && !noDirection && stixCoreObjectType
          ? [stixCoreObjectType]
          : null,
      startDate: startDate || null,
      endDate: endDate || null,
      field,
      operation: 'count',
      limit: 9,
      isTo: isTo || true,
      noDirection: noDirection || false,
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
                        item
                        xs={4}
                        style={{ padding: 0 }}
                      >
                        <div
                          className={classes.label}
                          style={{
                            color,
                            backgroundColor: hexToRGB(color, 0.3),
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
                  {t(NO_DATA_WIDGET_MESSAGE)}
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
        <Paper classes={{ root: classes.paperExplore }} variant="outlined">
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
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
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
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  isTo: PropTypes.bool,
  noDirection: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectStixCoreRelationshipsCloud);
