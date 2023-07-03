import React, { useEffect, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import {
  RelationManyToMany,
  CalendarMultiselectOutline,
} from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Drawer from '@mui/material/Drawer';
import Divider from '@mui/material/Divider';
import { makeStyles } from '@mui/styles';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import Filters from '../lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import { UserContext } from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles(() => ({
  bottomNav: {
    zIndex: 1000,
    display: 'flex',
    overflow: 'hidden',
  },
  divider: {
    display: 'inline-block',
    verticalAlign: 'middle',
    height: '100%',
    margin: '0 5px 0 5px',
  },
}));

const ContentKnowledgeTimeLineBar = ({
  handleTimeLineSearch,
  timeLineSearchTerm,
  timeLineDisplayRelationships,
  handleToggleTimeLineDisplayRelationships,
  timeLineFunctionalDate,
  handleToggleTimeLineFunctionalDate,
  timeLineFilters,
  handleAddTimeLineFilter,
  handleRemoveTimeLineFilter,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => {
      sub.unsubscribe();
    };
  });
  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => (
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
          PaperProps={{
            variant: 'elevation',
            elevation: 1,
            style: {
              paddingLeft: navOpen ? 185 : 60,
              bottom: bannerSettings.bannerHeightNumber,
            },
          }}
        >
          <div
            style={{
              height: 54,
              verticalAlign: 'top',
              transition: 'height 0.2s linear',
            }}
          >
            <div
              style={{
                verticalAlign: 'top',
                width: '100%',
                height: 54,
                paddingTop: 3,
              }}
            >
              <div
                style={{
                  float: 'left',

              height: '100%',
              display: 'flex',
            }}
          >
            <Tooltip
              title={
                timeLineDisplayRelationships
                  ? t('Do not display relationships')
                  : t('Display relationships')
              }
            >
              <span>
                <IconButton
                  color={timeLineDisplayRelationships ? 'secondary' : 'primary'}
                  size="large"
                  onClick={() => handleToggleTimeLineDisplayRelationships()}
                >
                  <RelationManyToMany />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip
              title={
                timeLineFunctionalDate
                  ? t('Use technical dates')
                  : t('Use functional dates')
              }
            >
              <span>
                <IconButton
                  color={timeLineFunctionalDate ? 'secondary' : 'primary'}
                  size="large"
                  onClick={() => handleToggleTimeLineFunctionalDate()}
                >
                  <CalendarMultiselectOutline />
                </IconButton>
              </span>
            </Tooltip>
            <Divider className={classes.divider} orientation="vertical" />
            <div style={{ margin: '9px 10px 0 10px' }}>
              <SearchInput
                variant="thin"
                onSubmit={handleTimeLineSearch}
                keyword={timeLineSearchTerm}
              />
            </div>
            <Divider className={classes.divider} orientation="vertical" />
            <div style={{ paddingTop: 4 }}>
              <Filters
                availableFilterKeys={[
                  'entity_type',
                  'markedBy',
                  'labelledBy',
                  'createdBy',
                  'relationship_type',
                ]}
                availableEntityTypes={[
                  'Stix-Domain-Object',
                  'Stix-Cyber-Observable',
                ]}
                handleAddFilter={handleAddTimeLineFilter}
                noDirectFilters={true}
              />
            </div>
            <div style={{ paddingTop: 3 }}>
              <FilterIconButton
                filters={timeLineFilters}
                handleRemoveFilter={handleRemoveTimeLineFilter}
                classNameNumber={1}
                redirection
              />
            </div>
          </div>
        </div>
      </div>
    </Drawer>)}
    </UserContext.Consumer>
  );
};

export default ContentKnowledgeTimeLineBar;
