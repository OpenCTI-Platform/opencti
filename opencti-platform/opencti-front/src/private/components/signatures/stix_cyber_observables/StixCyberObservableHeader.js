import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import ItemMarking from '../../../../components/ItemMarking';
import StixCyberObservablePopover from './StixCyberObservablePopover';
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

class StixCyberObservableHeaderComponent extends Component {
  render() {
    const { classes, variant, stixCyberObservable } = this.props;
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
          <StixCyberObservablePopover stixCyberObservableId={stixCyberObservable.id} />
        </div>
        {variant !== 'noMarking' ? (
          <div className={classes.marking}>
            {pathOr([], ['markingDefinitions', 'edges'], stixCyberObservable).map(
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

StixCyberObservableHeaderComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
};

const StixCyberObservableHeader = createFragmentContainer(
  StixCyberObservableHeaderComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableHeader_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        observable_value
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

export default compose(withStyles(styles))(StixCyberObservableHeader);
