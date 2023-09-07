import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, DomainOutlined } from '@mui/icons-material';
import inject18n from '../../../components/i18n';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../utils/hooks/useGranted';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuSector extends Component {
  render() {
    const {
      t,
      location,
      id: sectorId,
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/entities/sectors"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <DomainOutlined className={classes.icon} fontSize="small" />
          {t('Sectors')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/entities/sectors/${sectorId}`}
          variant={
            location.pathname === `/dashboard/entities/sectors/${sectorId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/entities/sectors/${sectorId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!sectorId}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/entities/sectors/${sectorId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/entities/sectors/${sectorId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/entities/sectors/${sectorId}/knowledge`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!sectorId}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/entities/sectors/${sectorId}/analyses`}
          variant={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/analyses`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/analyses`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!sectorId}
        >
          {t('Analyses')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/entities/sectors/${sectorId}/sightings`}
          variant={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/sightings`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/sightings`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!sectorId}
        >
          {t('Sightings')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/entities/sectors/${sectorId}/files`}
            variant={
              location.pathname
              === `/dashboard/entities/sectors/${sectorId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/entities/sectors/${sectorId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
            disabled={!sectorId}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/entities/sectors/${sectorId}/history`}
          variant={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/entities/sectors/${sectorId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!sectorId}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuSector.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  id: PropTypes.string,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuSector);
