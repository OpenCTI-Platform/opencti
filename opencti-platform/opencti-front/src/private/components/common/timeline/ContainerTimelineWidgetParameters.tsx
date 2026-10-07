import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import {
  Checkbox,
  Combobox,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Text,
} from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import type { ContainerTimelineWidgetParametersSearchQuery } from './__generated__/ContainerTimelineWidgetParametersSearchQuery.graphql';
import type { ContainerTimelineWidgetParametersSelectedQuery } from './__generated__/ContainerTimelineWidgetParametersSelectedQuery.graphql';
import type { ContainerTimelineWidgetParameters as Parameters } from './ContainerTimelineWidget';
import { TIMELINE_CONTAINER_TYPES, TIMELINE_LANE_LABELS, TIMELINE_LANES, TIMELINE_ZOOM_LABELS, TIMELINE_ZOOM_WINDOWS } from './timelineUtils';

const SEARCH_SIZE = 20;

const containerSearchQuery = graphql`
  query ContainerTimelineWidgetParametersSearchQuery($search: String, $types: [String], $count: Int) {
    stixDomainObjects(search: $search, types: $types, first: $count, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const containerSelectedQuery = graphql`
  query ContainerTimelineWidgetParametersSelectedQuery($id: String!) {
    stixDomainObject(id: $id) {
      id
      entity_type
      representative {
        main
      }
    }
  }
`;

interface ContainerOption {
  value: string;
  label: string;
  type: string;
}

interface ContainerTimelineWidgetParametersProps {
  parameters: Parameters;
  onChange: (patch: Partial<Parameters>) => void;
  // A custom view always shows the timeline of the entity it is opened on
  showContainer?: boolean;
}

/** Parameters of the incident and case timeline widget: the container, the lanes and the window. */
const ContainerTimelineWidgetParameters = ({ parameters, onChange, showContainer = true }: ContainerTimelineWidgetParametersProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [options, setOptions] = useState<ContainerOption[]>([]);
  const [selected, setSelected] = useState<ContainerOption | null>(null);
  const latestSearch = useRef(0);
  const lanes = parameters.timeline_lanes ?? [];

  const search = (value: string) => {
    // Responses can arrive out of order: only the latest search may set the options
    latestSearch.current += 1;
    const searchId = latestSearch.current;
    fetchQuery<ContainerTimelineWidgetParametersSearchQuery>(containerSearchQuery, { search: value, types: TIMELINE_CONTAINER_TYPES, count: SEARCH_SIZE })
      .toPromise()
      .then((data) => {
        if (searchId !== latestSearch.current) return;
        setOptions((data?.stixDomainObjects?.edges ?? []).map(({ node }) => ({ value: node.id, label: node.representative.main, type: node.entity_type })));
      });
  };

  useEffect(() => {
    if (!showContainer || !parameters.container_id) {
      setSelected(null);
      return undefined;
    }
    // A lookup still running when the container changes or is cleared must not show its case
    let current = true;
    fetchQuery<ContainerTimelineWidgetParametersSelectedQuery>(containerSelectedQuery, { id: parameters.container_id })
      .toPromise()
      .then((data) => {
        if (!current) return;
        const node = data?.stixDomainObject;
        setSelected(node ? { value: node.id, label: node.representative.main, type: node.entity_type } : null);
      });
    return () => {
      current = false;
    };
  }, [showContainer, parameters.container_id]);

  const toggleLane = (lane: string) => {
    const next = lanes.includes(lane) ? lanes.filter((l) => l !== lane) : [...lanes, lane];
    onChange({ timeline_lanes: next });
  };

  return (
    <div style={{ marginTop: theme.spacing(2), display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }} data-testid="timeline-widget-parameters">
      {showContainer && (
        <Combobox<ContainerOption>
          className="w-full"
          options={options}
          value={selected}
          getOptionLabel={(option) => option.label}
          isOptionEqualToValue={(option, value) => option.value === value.value}
          onInputChange={(value) => search(typeof value === 'string' ? value : '')}
          onValueChange={(next) => {
            const option = next as ContainerOption | null;
            setSelected(option);
            onChange({ container_id: option?.value ?? null });
          }}
          renderOption={(option) => (
            <span style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
              <ItemIcon type={option.type} />
              <span>{option.label}</span>
            </span>
          )}
        >
          <ComboboxLabel>{t_i18n('Incident or case')}</ComboboxLabel>
          <ComboboxField startIcon={selected ? <ItemIcon type={selected.type} /> : undefined}>
            <ComboboxInput onFocus={() => search('')} />
            <ComboboxControls>
              <ComboboxClear />
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Incident or case')} />
        </Combobox>
      )}
      <div>
        <Text variant="content-caption" as="div" style={{ marginBottom: theme.spacing(1) }}>{t_i18n('Lanes (all when none is selected)')}</Text>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: theme.spacing(1) }}>
          {TIMELINE_LANES.map((lane) => (
            <Checkbox key={lane} label={t_i18n(TIMELINE_LANE_LABELS[lane])} checked={lanes.includes(lane)} onCheckedChange={() => toggleLane(lane)} />
          ))}
        </div>
      </div>
      <Select value={parameters.timeline_window ?? 'fit'} onValueChange={(value) => onChange({ timeline_window: value })}>
        <SelectLabel>{t_i18n('Time window')}</SelectLabel>
        <SelectTrigger aria-label={t_i18n('Time window')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Time window')}>
          {TIMELINE_ZOOM_WINDOWS.map((zoom) => (
            <SelectItem key={zoom} value={zoom}>{t_i18n(TIMELINE_ZOOM_LABELS[zoom])}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
};

export default ContainerTimelineWidgetParameters;
