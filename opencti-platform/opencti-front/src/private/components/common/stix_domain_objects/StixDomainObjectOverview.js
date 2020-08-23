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
import Theme from '../../../../components/ThemeDark';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemCreator from '../../../../components/ItemCreator';
import ItemRevoked from '../../../../components/ItemRevoked';
import StixDomainObjectLabels from './StixDomainObjectLabels';

const styles = () => ({
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
    backgroundColor: 'rgba(0, 150, 136, 0.3)',
    color: '#ffffff',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
});

class StixDomainObjectOverview extends Component {
  render() {
    const {
      t, fldt, classes, stixDomainObject,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
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
                  <InformationOutline
                    fontSize="small"
                    color={Theme.palette.primary.main}
                  />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: 0 }}>{stixDomainObject.standard_id}</pre>
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
                {stixDomainObject.spec_version}
              </Button>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={propOr(null, 'createdBy', stixDomainObject)}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
              </Typography>
              {fldt(stixDomainObject.created)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(stixDomainObject.modified)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Revoked')}
              </Typography>
              <ItemRevoked
                status={stixDomainObject.revoked}
                label={stixDomainObject.revoked ? t('Yes') : t('No')}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Other STIX IDs')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip title={t('Other known STIX IDs for this entity.')}>
                  <InformationOutline
                    fontSize="small"
                    color={Theme.palette.primary.main}
                  />
                </Tooltip>
              </div>
              <div className="clearfix" />
              <pre style={{ margin: '0 0 20px 0' }}>
                {stixDomainObject.stix_ids.length > 0
                  ? stixDomainObject.stix_ids.map((stixId) => `${stixId}\n`)
                  : '-'}
              </pre>
              <StixDomainObjectLabels
                labels={stixDomainObject.objectLabel}
                id={stixDomainObject.id}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Confidence level')}
              </Typography>
              <ItemConfidence confidence={stixDomainObject.confidence} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date (in this platform)')}
              </Typography>
              {fldt(stixDomainObject.created_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creator')}
              </Typography>
              <ItemCreator creator={stixDomainObject.creator} />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

StixDomainObjectOverview.propTypes = {
  stixDomainObject: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(StixDomainObjectOverview);
