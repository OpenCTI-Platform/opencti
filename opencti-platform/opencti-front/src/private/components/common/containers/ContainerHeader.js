import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import ContainerPopover from '../../analysis/containers/ContainerPopover';

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
  aliases: {
    marginRight: 7,
  },
  aliasesInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class ContainerHeaderComponent extends Component {
  render() {
    const { classes, container, variant } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(container.name, 80)}
        </Typography>
        <div className={classes.popover}>
          <ContainerPopover containerId={container.id} />
        </div>
        {variant !== 'noMarking' ? (
          <div className={classes.marking}>
            {pathOr([], ['objectMarking', 'edges'], container).map(
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

ContainerHeaderComponent.propTypes = {
  container: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ContainerHeader = createFragmentContainer(ContainerHeaderComponent, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
      name
      objectMarking {
        edges {
          node {
            id
            definition
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ContainerHeader);
