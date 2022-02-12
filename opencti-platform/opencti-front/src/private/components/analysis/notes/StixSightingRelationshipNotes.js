import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixSightingRelationshipNotesCards, {
  stixSightingRelationshipNotesCardsQuery,
} from './StixSightingRelationshipNotesCards';

class StixCoreObjectOrStixCoreRelationshipNotes extends Component {
  render() {
    const { t, stixSightingRelationshipId, marginTop } = this.props;
    return (
      <QueryRenderer
        query={stixSightingRelationshipNotesCardsQuery}
        variables={{ id: stixSightingRelationshipId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixSightingRelationshipNotesCards
                stixSightingRelationshipId={stixSightingRelationshipId}
                data={props}
                marginTop={marginTop}
              />
            );
          }
          return (
            <div style={{ height: '100%', marginTop: marginTop || 40 }}>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Notes about this sighting')}
              </Typography>
            </div>
          );
        }}
      />
    );
  }
}

StixCoreObjectOrStixCoreRelationshipNotes.propTypes = {
  t: PropTypes.func,
  stixSightingRelationshipId: PropTypes.string,
  isRelationship: PropTypes.bool,
  marginTop: PropTypes.number,
};

export default inject18n(StixCoreObjectOrStixCoreRelationshipNotes);
