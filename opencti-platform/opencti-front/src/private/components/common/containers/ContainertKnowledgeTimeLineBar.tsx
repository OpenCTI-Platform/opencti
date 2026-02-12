import React, { FunctionComponent, SyntheticEvent, useEffect, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { RelationManyToMany, CalendarMultiselectOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Drawer from '@mui/material/Drawer';
import Divider from '@mui/material/Divider';
import { makeStyles } from '@mui/styles';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import Filters from '../lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import useAuth, { FilterDefinition, UserContext } from '../../../../utils/hooks/useAuth';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { Stack } from '@mui/material';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  bottomNav: {
    zIndex: 1,
    display: 'flex',
    overflow: 'hidden',
  },
}));

interface ContentKnowledgeTimeLineBarProps {
  handleTimeLineSearch: (search: string) => void;
  timeLineSearchTerm: string;
  timeLineDisplayRelationships: boolean;
  handleToggleTimeLineDisplayRelationships: () => void;
  timeLineFunctionalDate: boolean;
  handleToggleTimeLineFunctionalDate: () => void;
  timeLineFilters: FilterGroup;
  handleAddTimeLineFilter: (filterKeysSchema: Map<string, Map<string, FilterDefinition>>, key: string, id: string | null, op?: string, event?: SyntheticEvent) => void;
  handleRemoveTimeLineFilter: (key: string, id?: string) => void;
  handleSwitchFilterLocalMode: (filter: Filter) => void;
  handleSwitchFilterGlobalMode: () => void;
}

// TODO Fix ContentKnowledge
const ContentKnowledgeTimeLineBar: FunctionComponent<ContentKnowledgeTimeLineBarProps> = ({
  handleTimeLineSearch,
  timeLineSearchTerm,
  timeLineDisplayRelationships,
  handleToggleTimeLineDisplayRelationships,
  timeLineFunctionalDate,
  handleToggleTimeLineFunctionalDate,
  timeLineFilters,
  handleAddTimeLineFilter,
  handleRemoveTimeLineFilter,
  handleSwitchFilterLocalMode,
  handleSwitchFilterGlobalMode,
}) => {
  const { filterKeysSchema } = useAuth().schema;
  const classes = useStyles();
  const draftContext = useDraftContext();
  const { t_i18n } = useFormatter();
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  const posBottom = draftContext ? 69 : 0; // 69 is the height of the Draft toolbar.

  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => {
      sub.unsubscribe();
    };
  });

  const handleAddFilter = (key: string, id: string | null, op = 'eq', event?: SyntheticEvent) => {
    handleAddTimeLineFilter(filterKeysSchema, key, id, op, event);
  };

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => (
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
          slotProps={{
            paper: {
              variant: 'elevation',
              elevation: 1,
              style: {
                paddingLeft: navOpen ? 185 : 60,
                bottom: (bannerSettings?.bannerHeightNumber ?? 0) + posBottom,
              },
            },
          }}
        >
          <div
            style={{
              height: 'auto',
              maxHeight: 108,
              transition: 'min-height 0.2s linear',
              paddingLeft: 8,
            }}
          >
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              sx={{
                minHeight: 50,
              }}
            >
              <Tooltip
                title={
                  timeLineDisplayRelationships
                    ? t_i18n('Do not display relationships')
                    : t_i18n('Display relationships')
                }
              >
                <span>
                  <IconButton
                    color={timeLineDisplayRelationships ? 'secondary' : 'primary'}
                    onClick={() => handleToggleTimeLineDisplayRelationships()}
                  >
                    <RelationManyToMany />
                  </IconButton>
                </span>
              </Tooltip>
              <Tooltip
                title={
                  timeLineFunctionalDate
                    ? t_i18n('Use technical dates')
                    : t_i18n('Use functional dates')
                }
              >
                <span>
                  <IconButton
                    color={timeLineFunctionalDate ? 'secondary' : 'primary'}
                    onClick={() => handleToggleTimeLineFunctionalDate()}
                  >
                    <CalendarMultiselectOutline />
                  </IconButton>
                </span>
              </Tooltip>

              <Divider orientation="vertical" flexItem sx={{ ml: 0.5, mr: 0.5 }} />

              <div style={{ flexGrow: 0 }}>
                <SearchInput
                  variant="thin"
                  onSubmit={handleTimeLineSearch}
                  keyword={timeLineSearchTerm}
                />
              </div>

              <Divider orientation="vertical" flexItem sx={{ ml: 0.5, mr: 0.5 }} />

              <div style={{ paddingTop: 0 }}>
                <Filters
                  availableFilterKeys={[
                    'entity_type',
                    'objectMarking',
                    'objectLabel',
                    'createdBy',
                    'relationship_type',
                  ]}
                  availableEntityTypes={[
                    'Stix-Domain-Object',
                    'Stix-Cyber-Observable',
                  ]}
                  handleAddFilter={handleAddFilter}
                />
              </div>

              <div style={{ flexGrow: 1 }}>
                <FilterIconButton
                  filters={timeLineFilters}
                  handleRemoveFilter={handleRemoveTimeLineFilter}
                  handleSwitchLocalMode={handleSwitchFilterLocalMode}
                  handleSwitchGlobalMode={handleSwitchFilterGlobalMode}
                  redirection
                  availableEntityTypes={[
                    'Stix-Domain-Object',
                    'Stix-Cyber-Observable',
                  ]}
                />
              </div>
            </Stack>
          </div>
        </Drawer>
      )}
    </UserContext.Consumer>
  );
};

export default ContentKnowledgeTimeLineBar;
