import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import ItemMarking from '../../../../components/ItemMarking';
import IndicatorPopover from './IndicatorPopover';
import { truncate } from '../../../../utils/String';

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
        {variant !== 'noMarking' ? (
          <div className={classes.marking}>
            {pathOr([], ['markingDefinitions', 'edges'], indicator).map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                />
              ),
            )}
          </div>
        ) : (
          ''
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

const IndicatorHeader = createFragmentContainer(
  IndicatorHeaderComponent,
  {
    indicator: graphql`
      fragment IndicatorHeader_indicator on Indicator {
        id
        entity_type
        name
        markingDefinitions {
          edges {
            node {
              id
              definition
            }
          }
        }
      }
    `,
  },
);

export default compose(withStyles(styles))(IndicatorHeader);
