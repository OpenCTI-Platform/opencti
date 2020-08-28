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
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

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
    const {
      classes, container, variant, PopoverComponent, fd,
    } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(
            container.name
              || container.attribute_abstract
              || container.opinion
              || `${fd(container.first_observed)} - ${fd(
                container.last_observed,
              )}`,
            80,
          )}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div className={classes.popover}>
            {React.cloneElement(PopoverComponent, { id: container.id })}
          </div>
        </Security>
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
  PopoverComponent: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ContainerHeader = createFragmentContainer(ContainerHeaderComponent, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      id
      ... on Report {
        name
      }
      ... on Note {
        attribute_abstract
      }
      ... on Opinion {
        opinion
      }
      ... on ObservedData {
        first_observed
        last_observed
      }
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
