import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, take, sortWith, prop, ascend, pipe,
} from 'ramda';
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
  tagInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
  tagInSearch: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 0 0',
  },
  tagInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class StixObjectTags extends Component {
  hexToRGB(hex) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgb(${r}, ${g}, ${b}, 0.08)`;
  }

  render() {
    const {
      classes, tags, t, onClick, variant,
    } = this.props;
    let style = classes.tag;
    if (variant === 'inList') {
      style = classes.tagInList;
    }
    if (variant === 'inSearch') {
      style = classes.tagInSearch;
    }
    const tagsNodes = pipe(
      map((n) => n.node),
      sortWith([ascend(prop('value'))]),
    )(tags.edges);
    return (
      <div className={classes.tags}>
        {tagsNodes.length > 0 ? (
          map(
            (tag) => (
              <Chip
                key={tag.id}
                variant="outlined"
                classes={{ root: style }}
                label={tag.value}
                style={{
                  color: tag.color,
                  borderColor: tag.color,
                  backgroundColor: this.hexToRGB(tag.color),
                }}
                onClick={
                  typeof onClick === 'function'
                    ? onClick.bind(this, 'tags', tag.id, tag.value)
                    : null
                }
              />
            ),
            take(3, tagsNodes),
          )
        ) : (
          <Chip
            classes={{ root: style }}
            variant="outlined"
            label={t('No tag')}
            style={{
              color: '#ffffff',
              borderColor: '#ffffff',
              backgroundColor: this.hexToRGB('#ffffff'),
            }}
            onClick={
              typeof onClick === 'function'
                ? onClick.bind(this, 'tags', null, null)
                : null
            }
          />
        )}
      </div>
    );
  }
}

StixObjectTags.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  tags: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixObjectTags);
