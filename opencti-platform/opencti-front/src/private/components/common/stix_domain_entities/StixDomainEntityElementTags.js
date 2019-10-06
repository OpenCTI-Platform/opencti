import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, take } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  tags: {
    margin: 0,
    padding: 0,
  },
  tag: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
  },
  tagInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class StixDomainEntityElementTags extends Component {
  render() {
    const {
      classes, tags, t, onClick,
    } = this.props;
    return (
      <div className={classes.tags}>
        {tags.edges.length > 0 ? (
          map(
            (tagEdge) => (
              <Chip
                key={tagEdge.node.id}
                classes={{ root: classes.tag }}
                label={tagEdge.node.value}
                style={{ backgroundColor: tagEdge.node.color }}
                onClick={onClick.bind(this, 'tags', tagEdge.node.value)}
              />
            ),
            take(3, tags.edges),
          )
        ) : (
          <Chip
            classes={{ root: classes.tag }}
            label={t('No tag')}
            style={{ backgroundColor: '#ffffff', color: '#000000' }}
            onClick={onClick.bind(this, 'tags', null)}
          />
        )}
      </div>
    );
  }
}

StixDomainEntityElementTags.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  onClick: PropTypes.func,
  tags: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityElementTags);
