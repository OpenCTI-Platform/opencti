import React, { Fragment, FunctionComponent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import { InformationOutline } from 'mdi-material-ui';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import Box from '@mui/material/Box';
import { Stack } from '@mui/material';
import CodeBlock from '@components/common/CodeBlock';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import { Filter, FilterGroup } from '../../utils/filters/filtersHelpers-types';

interface DisplayFiltersValuesProps {
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  values: string[];
  mode?: string;
}

const DisplayFiltersValues: FunctionComponent<DisplayFiltersValuesProps> = ({
  filtersRepresentativesMap,
  values,
  mode,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      {values.map((value, j) => (
        <Fragment key={value}>
          <span key={value}>
            {' '}
            {filtersRepresentativesMap.get(value) ? filtersRepresentativesMap.get(value)?.value : value}{' '}
          </span>
          {j + 1 < values.length && (
            <Box
              sx={{
                paddingTop: 2,
                textTransform: 'uppercase',
                fontFamily: 'Consolas, monaco, monospace',
                backgroundColor: mode ? 'rgba(255, 255, 255, .1)' : 'rgba(255, 255, 255, .0)',
                fontWeight: 'bold',
                display: 'inline-block',
                padding: '8px',
              }}
            >
              {t_i18n(mode ?? 'or')}
            </Box>
          )}
        </Fragment>
      ))}
    </>
  );
};

interface DisplayFilterGroupsProps {
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterGroups: FilterGroup[];
  filterMode: string;
}

const DisplayFiltersFilterGroups: FunctionComponent<DisplayFilterGroupsProps> = ({
  filtersRepresentativesMap,
  filterGroups,
  filterMode,
}) => {
  const { t_i18n } = useFormatter();

  const displayFilterValues = (f: Filter) => {
    const { key, values, mode } = f;

    // case of filters with subfilters
    if (key === 'regardingOf' || key === 'dynamicRegardingOf') {
      return (
        <>
          {values
            .filter((v) => v.key === 'relationship_type')
            .flat()
            .map((value) => {
              return (
                <span key="relationship_type">
                  <DisplayFiltersValues
                    filtersRepresentativesMap={filtersRepresentativesMap}
                    values={value.values}
                  />
                </span>
              );
            })}
          {values.filter((v) => v.key === 'id' || v.key === 'dynamic').length > 0
            && (
              <Box
                sx={{
                  paddingTop: 2,
                  textTransform: 'uppercase',
                  fontFamily: 'Consolas, monaco, monospace',
                  backgroundColor: 'rgba(255, 255, 255, .1)',
                  fontWeight: 'bold',
                  display: 'inline-block',
                  margin: '0 8px',
                  padding: '8px',
                }}
              >
                {t_i18n('WITH')}
              </Box>
            )
          }
          {values.filter((v) => v.key === 'id').flat().map((value) => {
            return (
              <span key="id">
                <DisplayFiltersValues
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  values={value.values}
                />
              </span>
            );
          })}
          {values.filter((v) => v.key === 'dynamic').flat().map((value) => {
            return (
              <span key="id">
                <DisplayFiltersFilterGroups
                  filterGroups={value.values}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  filterMode="and"
                />
              </span>
            );
          })}
        </>
      );
    }

    // case of filters with filters in 'values'
    if (key === 'dynamicTo' || key === 'dynamicFrom') {
      return (
        <DisplayFiltersFilterGroups
          filterGroups={values}
          filtersRepresentativesMap={filtersRepresentativesMap}
          filterMode={mode ?? 'or'}
        />
      );
    }

    // classic filters
    return (
      <DisplayFiltersValues
        filtersRepresentativesMap={filtersRepresentativesMap}
        values={values}
        mode={mode ?? 'or'}
      />
    );
  };

  const displayFilterFilters = (filters: Filter[], parentMode: string) => {
    return filters.map((f, i) => {
      const { key, operator, id } = f;
      return (
        <Box
          key={id ?? key}
          sx={{
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: '8px',
            alignItems: 'center',
          }}
        >
          {i !== 0 && (
            <Box
              sx={{
                textTransform: 'uppercase',
                fontWeight: 'bold',
                display: 'inline-block',
                borderRadius: '24px',
                padding: '8px 16px',
                fontFamily: 'Consolas, monaco, monospace',
                backgroundColor: '#01478d',
              }}
            >
              {parentMode}
            </Box>
          )}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              borderRadius: '24px',
              padding: '0 16px',
              backgroundColor: 'rgba(255, 255, 255, 0.16)',
              width: 'fit-content',
            }}
          >
            <span>{t_i18n(key)}</span>
            <Box
              sx={{
                textTransform: 'uppercase',
                fontFamily: 'Consolas, monaco, monospace',
                backgroundColor: 'rgb(74 117 162)',
                fontWeight: 'bold',
                display: 'inline-block',
                margin: '0 8px',
                padding: '8px',
              }}
            >
              {' '}
              {operator}
            </Box>
            <Box sx={{ display: 'inline-block' }}>
              {displayFilterValues(f)}
            </Box>
          </Box>
        </Box>
      );
    });
  };

  return filterGroups.map((f, i) => {
    return (
      <Fragment key={i}>
        {i !== 0 && (
          <Box
            sx={{
              textTransform: 'uppercase',
              fontWeight: 'bold',
              display: 'inline-block',
              borderRadius: '24px',
              padding: '8px 16px',
              fontFamily: 'Consolas, monaco, monospace',
              height: 'fit-content',
              backgroundColor: '#01478d',
              marginBottom: '8px',
            }}
          >
            {filterMode}
          </Box>
        )}
        <Box
          sx={{
            padding: '16px',
            backgroundColor: 'rgba(0,0,0, 0.1)',
            marginBottom: '16px',
          }}
        >
          <Stack sx={{ gap: '8px', paddingBottom: '8px' }}>
            {displayFilterFilters(f.filters, f.mode)}
          </Stack>
          {f.filterGroups.length > 0 && (
            <Stack direction="row">
              <Box
                sx={{
                  textTransform: 'uppercase',
                  fontWeight: 'bold',
                  borderRadius: '24px',
                  padding: '8px 16px',
                  fontFamily: 'Consolas, monaco, monospace',
                  backgroundColor: '#01478d',
                  marginRight: '8px',
                  height: 'fit-content',
                }}
              >
                {f.mode}
              </Box>
              <DisplayFiltersFilterGroups
                filtersRepresentativesMap={filtersRepresentativesMap}
                filterGroups={f.filterGroups}
                filterMode={filterMode}
              />
            </Stack>
          )}
        </Box>
      </Fragment>
    );
  });
};

interface DisplayFilterGroupProps {
  filterObj: FilterGroup;
  filterMode: string;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  classFilter: string;
  classChipLabel: string;
}

const DisplayFilterGroup: FunctionComponent<DisplayFilterGroupProps> = ({
  filterObj,
  filterMode,
  filtersRepresentativesMap,
  classFilter,
  classChipLabel,
}) => {
  const { filterGroups } = filterObj;
  const [open, setOpen] = useState(false);
  const { t_i18n } = useFormatter();
  const handleClickOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };

  return (
    <>
      <Chip
        classes={{ root: classFilter, label: classChipLabel }}
        color="warning"
        onClick={handleClickOpen}
        label={(
          <>
            {t_i18n('Filters are not fully displayed')}
            <InformationOutline
              fontSize="small"
              color="secondary"
            />
          </>
        )}
      />

      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="filter-groups-dialog-title"
        aria-describedby="Show Filter groups configuration"
      >
        <DialogTitle id="filter-groups-dialog-title">
          This filter contains imbricated filter groups, that are not fully
          supported yet in the platform display and can only be edited via the
          API. They might have been created via the API or a migration from a
          previous filter format. For your information, here is the content of
          the filter object
        </DialogTitle>
        <DialogContent>
          <Typography
            variant="h2"
            sx={{ textTransform: 'none' }}
            gutterBottom={true}
          >
            Your filter group cannot be modified yet :
          </Typography>
          <DisplayFiltersFilterGroups
            filtersRepresentativesMap={filtersRepresentativesMap}
            filterGroups={filterGroups}
            filterMode={filterMode}
          />
          <Typography
            variant="h2"
            sx={{ textTransform: 'none' }}
            gutterBottom={true}
          >
            The complete Filter object is as follows:
          </Typography>
          <CodeBlock
            code={JSON.stringify(filterObj, null, 2)}
            language="json"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose} autoFocus>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default DisplayFilterGroup;
