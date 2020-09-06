import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core';
import Typography from '@material-ui/core/Typography';
import { Map, TileLayer } from 'react-leaflet';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class LocationMiniMap extends Component {
  constructor(props) {
    super(props);
    this.state = {
      zoom: 13,
      lat: props.lat,
      lng: props.lng,
    };
  }

  render() {
    const { t } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginBottom: 10 }}
        >
          {t('Mini map')}
        </Typography>
        <Map
          center={[45.4, -75.7]}
          zoom={12}
          attributionControl={false}
          zoomControl={false}
          dragging={false}
          boxZoom={false}
          doubleClickZoom={false}
          scrollWheelZoom={false}
          touchZoom={false}
          keyboard={false}
        >
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        </Map>
      </div>
    );
  }
}

LocationMiniMap.propTypes = {
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(LocationMiniMap);
