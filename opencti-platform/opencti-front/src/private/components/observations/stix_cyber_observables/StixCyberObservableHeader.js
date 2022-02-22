import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import ItemMarking from '../../../../components/ItemMarking';
import StixCyberObservablePopover from './StixCyberObservablePopover';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'right',
    overflowX: 'hidden',
  },
});

class StixCyberObservableHeaderComponent extends Component {
  render() {
    const { classes, variant, stixCyberObservable, isArtifact } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(stixCyberObservable.observable_value, 50)}
        </Typography>
        <div className={classes.popover}>
          <StixCyberObservablePopover
            stixCyberObservableId={stixCyberObservable.id}
            isArtifact={isArtifact}
          />
        </div>
        <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
        {variant !== 'noMarking' && (
          <div className={classes.marking}>
            {pathOr([], ['objectMarking', 'edges'], stixCyberObservable).map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
            )}
          </div>
        )}
        <div className="clearfix" />
      </div>
    );
  }
}

StixCyberObservableHeaderComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  isArtifact: PropTypes.bool,
};

const StixCyberObservableHeader = createFragmentContainer(
  StixCyberObservableHeaderComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableHeader_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        observable_value
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
            }
          }
        }
      }
    `,
  },
);

export default compose(withStyles(styles))(StixCyberObservableHeader);
