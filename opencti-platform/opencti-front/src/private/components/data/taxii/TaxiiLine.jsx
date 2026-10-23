import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { styled } from '@mui/material/styles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { DatabaseExportOutline } from 'mdi-material-ui';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import TaxiiPopover from './TaxiiPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import ItemCopy from '../../../../components/ItemCopy';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { EMPTY_VALUE } from '../../../../utils/String';

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

const itemSx = {
  paddingLeft: '10px',
  height: 50,
};

const itemIconSx = {
  color: (theme) => theme.palette.primary.main,
};

class TaxiiLineLineComponent extends Component {
  render() {
    const { node, dataColumns, paginationOptions } = this.props;
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={(
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <TaxiiPopover
              taxiiCollectionId={node.id}
              paginationOptions={paginationOptions}
            />
          </Security>
        )}
      >
        <ListItemButton
          sx={itemSx}
          component="a"
          href={`/taxii2/root/collections/${node.id}/objects/`}
          target="_blank"
        >
          <ListItemIcon sx={itemIconSx}>
            <DatabaseExportOutline />
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
                  style={{ width: dataColumns.description.width }}
                >
                  <FieldOrEmpty source={node.description}>{node.description}</FieldOrEmpty>
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.id.width, paddingRight: 10 }}
                >
                  <ItemCopy content={node.id} variant="inLine" />
                </BodyItem>
                <FiltersItem
                  style={{ width: dataColumns.filters.width }}
                >
                  {isFilterGroupNotEmpty(filters)
                    ? (
                        <FilterIconButton
                          filters={filters}
                          dataColumns={dataColumns}
                          variant="small"
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

TaxiiLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  fd: PropTypes.func,
};

const TaxiiLineFragment = createFragmentContainer(TaxiiLineLineComponent, {
  node: graphql`
    fragment TaxiiLine_node on TaxiiCollection {
      id
      name
      description
      filters
    }
  `,
});

export const TaxiiLine = inject18n(TaxiiLineFragment);

class TaxiiDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={itemSx}
        divider={true}
        secondaryAction={<MoreVert />}
      >
        <ListItemIcon sx={itemIconSx}>
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
                style={{ width: dataColumns.description.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.id.width }}
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

TaxiiDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const TaxiiLineDummy = inject18n(TaxiiDummyComponent);
