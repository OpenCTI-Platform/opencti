import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemCreator from '../../../../components/ItemCreator';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import ItemScore from '../../../../components/ItemScore';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.chip,
    color: '#ffffff',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
});

class StixCyberObservableOverview extends Component {
  render() {
    const {
      t, fldt, classes, stixCyberObservable,
    } = this.props;
    const stixIds = stixCyberObservable.x_opencti_stix_ids || [];
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Standard STIX ID')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip
                  title={t(
                    'In OpenCTI, a predictable STIX ID is generated based on one or multiple attributes of the entity.',
                  )}
                >
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>{stixCyberObservable.standard_id}</pre>
            </Grid>
            <Grid item={true} xs={12}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Other STIX IDs')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip title={t('Other known STIX IDs for this entity.')}>
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>
                {stixIds.length > 0
                  ? stixIds.map((stixId) => `${stixId}\n`)
                  : '-'}
              </pre>
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Observable type')}
              </Typography>
              <Chip
                classes={{ root: classes.chip }}
                style={{
                  backgroundColor: 'rgba(32, 58, 246, 0.08)',
                  color: '#203af6',
                  border: '1px solid #203af6',
                }}
                label={t(`entity_${stixCyberObservable.entity_type}`)}
              />

              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Score')}
              </Typography>
              <ItemScore score={stixCyberObservable.x_opencti_score} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('STIX version')}
              </Typography>
              <Button
                variant="outlined"
                size="small"
                style={{ cursor: 'default' }}
              >
                {stixCyberObservable.spec_version}
              </Button>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={propOr(null, 'createdBy', stixCyberObservable)}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <StixCoreObjectLabelsView
                labels={stixCyberObservable.objectLabel}
                id={stixCyberObservable.id}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creator')}
              </Typography>
              <ItemCreator creator={stixCyberObservable.creator} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
              </Typography>
              {fldt(stixCyberObservable.created_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(stixCyberObservable.updated_at)}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

StixCyberObservableOverview.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableOverview);
