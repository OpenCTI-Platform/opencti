import React, { useState } from 'react';
import { Link } from 'react-router';
import { Chip } from '@filigran/design-system';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemText from '@mui/material/ListItemText';
import Collapse from '@mui/material/Collapse';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';

/**
 * Number of touched elements requested per work. The `touchedElements(first: ...)`
 * literal of the StixCoreObjectEnrichmentLines fragment must match it.
 */
export const TOUCHED_ELEMENTS_PAGE_SIZE = 100;

interface TouchedElement {
  id?: string;
  entity_type?: string;
  parent_types?: ReadonlyArray<string>;
  representative?: { main: string } | null;
}

interface IdentifiedTouchedElement extends TouchedElement {
  id: string;
}

interface TouchedWork {
  status: string;
  touchedElements?: ReadonlyArray<TouchedElement | null> | null;
  touchedElementsTruncated?: boolean | null;
}

interface StixCoreObjectEnrichmentWorkTouchedElementsProps {
  work: TouchedWork;
  first: number;
}

/**
 * Translation key of the type of a touched element: relationships (except sightings, which have
 * an entity label) use the `relationship_` keys, like the rest of the application.
 */
const touchedElementTypeKey = (element: TouchedElement) => {
  const isRelationship = element.parent_types?.includes('basic-relationship')
    && element.entity_type !== 'stix-sighting-relationship';
  return isRelationship
    ? `relationship_${element.entity_type}`
    : `entity_${element.entity_type}`;
};

/**
 * Expandable list of the elements a completed enrichment work created or changed.
 * Renders nothing while the work is not complete, or when its touched elements were never recorded
 * (`touchedElements` is null: not an enrichment work, or a work completed before the feature existed).
 * A work that touched nothing visible shows a "0" count without an expander.
 */
const StixCoreObjectEnrichmentWorkTouchedElements = ({
  work,
  first,
}: StixCoreObjectEnrichmentWorkTouchedElementsProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  if (work.status !== 'complete' || !work.touchedElements) {
    return null;
  }

  const touched = work.touchedElements.filter((e): e is IdentifiedTouchedElement => !!e?.id);
  // The list is capped by `first` and by the platform: say so instead of showing a wrong total
  const count = `${touched.length}${touched.length >= first || work.touchedElementsTruncated ? '+' : ''}`;

  if (touched.length === 0) {
    return (
      <ListItem dense={true} style={{ paddingLeft: 64, gap: 8 }}>
        <ListItemText primary={t_i18n('Elements touched by this enrichment')} />
        <Chip label={count} />
      </ListItem>
    );
  }

  return (
    <>
      <ListItemButton
        dense={true}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        style={{ paddingLeft: 64, gap: 8 }}
      >
        <ListItemText primary={t_i18n('Elements touched by this enrichment')} />
        <Chip label={count} />
        {open ? <ExpandLess /> : <ExpandMore />}
      </ListItemButton>
      <Collapse in={open} timeout="auto" unmountOnExit>
        <List
          component="div"
          disablePadding={true}
          style={{ paddingLeft: 64 }}
        >
          {touched.map((element) => (
            <ListItemButton
              key={element.id}
              component={Link}
              to={`/dashboard/id/${element.id}`}
              dense={true}
            >
              <ListItemText
                primary={element.representative?.main ?? element.id}
                secondary={t_i18n(touchedElementTypeKey(element))}
              />
            </ListItemButton>
          ))}
        </List>
      </Collapse>
    </>
  );
};

export default StixCoreObjectEnrichmentWorkTouchedElements;
