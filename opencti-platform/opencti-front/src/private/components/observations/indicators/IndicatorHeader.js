import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import ItemMarking from '../../../../components/ItemMarking';
import IndicatorPopover from './IndicatorPopover';
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

class IndicatorHeaderComponent extends Component {
  render() {
    const { classes, variant, indicator } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(indicator.name, 50)}
        </Typography>
        <div className={classes.popover}>
          <IndicatorPopover indicatorId={indicator.id} />
        </div>
        <StixCoreObjectEnrichment stixCoreObjectId={indicator.id} />
        {variant !== 'noMarking' && (
          <div className={classes.marking}>
            {pathOr([], ['objectMarking', 'edges'], indicator).map(
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

IndicatorHeaderComponent.propTypes = {
  indicator: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
};

const IndicatorHeader = createFragmentContainer(IndicatorHeaderComponent, {
  indicator: graphql`
    fragment IndicatorHeader_indicator on Indicator {
      id
      entity_type
      name
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
});

export default compose(withStyles(styles))(IndicatorHeader);
