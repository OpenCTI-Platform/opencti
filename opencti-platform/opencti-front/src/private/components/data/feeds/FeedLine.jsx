import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import { FileDelimitedOutline } from 'mdi-material-ui';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { styled } from '@mui/material/styles';
import FeedPopover from './FeedPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { EMPTY_VALUE } from '../../../../utils/String';
import { stopLinkNavigation } from '../../../../utils/domEvent';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const BodyItem = styled('div')({
  height: 40,
  display: 'flex',
  alignItems: 'center',
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
});

const FiltersItem = styled('div')({
  height: 40,
  display: 'flex',
  alignItems: 'center',
  float: 'left',
  paddingRight: 10,
});

class FeedLineLineComponent extends Component {
  render() {
    const { node, dataColumns, paginationOptions, t } = this.props;
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={(
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <FeedPopover feedId={node.id} paginationOptions={paginationOptions} />
          </Security>
        )}
      >
        <ListItemButton
          sx={{ paddingLeft: '10px', height: 50 }}
          component="a"
          href={`/feeds/${node.id}`}
          target="_blank" // open in new tab

        >
          <ListItemIcon sx={{ color: 'primary.main' }}>
            <FileDelimitedOutline />
          </ListItemIcon>
          <ListItemText
            primary={(
              <>
                <BodyItem
                  style={{ width: dataColumns.name.width }}
                >
                  {node.name}
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.feed_types.width }}
                >
                  {node.feed_types.map((type) => t(`entity_${type}`)).join(', ')}
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.rolling_time.width }}
                >
                  <code>{node.rolling_time}</code>
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.columns.width }}
                >
                  {node.feed_attributes.map((n) => n.attribute).join(`${node.separator} `)}
                </BodyItem>
                <FiltersItem
                  style={{ width: dataColumns.filters.width }}
                  onClick={stopLinkNavigation}
                  onAuxClick={stopLinkNavigation}
                >
                  {isFilterGroupNotEmpty(filters)
                    ? (
                        <FilterIconButton
                          filters={filters}
                          variant="small"
                          dataColumns={dataColumns}
                          showGroupsSummaryButtonOnReadOnly
                        />
                      )
                    : EMPTY_VALUE}
                </FiltersItem>
              </>
            )}
          />
        </ListItemButton>
      </ListItem>
    );
  }
}

FeedLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
};

const FeedLineFragment = createFragmentContainer(FeedLineLineComponent, {
  node: graphql`
    fragment FeedLine_node on Feed {
      id
      name
      separator
      rolling_time
      filters
      include_header
      feed_types
      feed_attributes {
        attribute
        multi_match_strategy
        multi_match_separator
        mappings {
          type
          attribute
          relationship_type
          target_entity_type
        }
      }
    }
  `,
});

export const FeedLine = inject18n(FeedLineFragment);

class FeedDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={{ paddingLeft: '10px', height: 50 }}
        divider={true}
        secondaryAction={<MoreVert />}
      >
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <BodyItem
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.feed_types.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.rolling_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.columns.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.filters.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
            </>
          )}
        />
      </ListItem>
    );
  }
}

FeedDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const FeedLineDummy = inject18n(FeedDummyComponent);
