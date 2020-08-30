import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectNotesCards, {
  stixCoreObjectNotesCardsQuery,
} from './StixCoreObjectNotesCards';
import StixCoreRelationshipNotesCards, {
  stixCoreRelationshipNotesCardsQuery,
} from './StixCoreRelationshipNotesCards';
import { QueryRenderer } from '../../../../relay/environment';

class StixCoreObjectOrStixCoreRelationshipNotes extends Component {
  render() {
    const {
      t,
      stixCoreObjectOrStixCoreRelationshipId,
      isRelationship,
      inputType,
      marginTop,
    } = this.props;
    if (isRelationship) {
      return (
        <QueryRenderer
          query={stixCoreRelationshipNotesCardsQuery}
          variables={{ id: stixCoreObjectOrStixCoreRelationshipId, count: 200 }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreRelationshipNotesCards
                  stixCoreRelationshipId={
                    stixCoreObjectOrStixCoreRelationshipId
                  }
                  inputType={inputType}
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
                  {t('Notes about this relationship')}
                </Typography>
              </div>
            );
          }}
        />
      );
    }
    return (
      <QueryRenderer
        query={stixCoreObjectNotesCardsQuery}
        variables={{ id: stixCoreObjectOrStixCoreRelationshipId, count: 200 }}
        render={({ props }) => {
          if (props) {
            return (
              <StixCoreObjectNotesCards
                stixCoreObjectId={stixCoreObjectOrStixCoreRelationshipId}
                inputType={inputType}
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
                {t('Notes about this entity')}
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
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  isRelationship: PropTypes.bool,
  inputType: PropTypes.string,
  marginTop: PropTypes.number,
};

export default inject18n(StixCoreObjectOrStixCoreRelationshipNotes);
