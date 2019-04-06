import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import StixObservablePopover from './StixObservablePopover';
import { truncate } from '../../../utils/String';

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

class StixObservableHeaderComponent extends Component {
  render() {
    const {
      t, classes, variant, stixObservable,
    } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(stixObservable.observable_value, 80)}
        </Typography>
        <div className={classes.popover}>
          <StixObservablePopover stixObservableId={stixObservable.id} />
        </div>
        {variant !== 'noMarking' ? (
          <div className={classes.marking}>
            {pathOr([], ['markingDefinitions', 'edges'], stixObservable).map(
              markingDefinition => (
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

StixObservableHeaderComponent.propTypes = {
  stixObservable: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const StixObservableHeader = createFragmentContainer(
  StixObservableHeaderComponent,
  {
    stixObservable: graphql`
      fragment StixObservableHeader_stixObservable on StixObservable {
        id
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

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableHeader);
