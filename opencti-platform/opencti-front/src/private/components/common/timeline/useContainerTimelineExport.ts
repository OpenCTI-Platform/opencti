import { useState } from 'react';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import type { RelayError } from '../../../../relay/relayTypes';
import { useFormatter } from '../../../../components/i18n';
import { htmlToPdf } from '../../../../utils/htmlToPdf/htmlToPdf';
import { MAX_WIDTH_PORTRAIT } from '../../../../utils/htmlToPdf/utils/constants';
import { containerTimelineExportFileQuery, containerTimelineExportQuery } from './ContainerTimelineMutations';
import type { ContainerTimelineMutationsExportFileQuery } from './__generated__/ContainerTimelineMutationsExportFileQuery.graphql';
import type {
  ContainerTimelineMutationsExportQuery,
  ContainerTimelineMutationsExportQuery$variables,
  TimelineEventKind,
  TimelineEventSource,
  TimelineLane as GqlTimelineLane,
} from './__generated__/ContainerTimelineMutationsExportQuery.graphql';
import {
  buildTimelineFileName,
  fitSvgToWidth,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_ANCHOR_LABELS,
  TIMELINE_KIND_LABELS,
  TIMELINE_LANE_LABELS,
  TIMELINE_LANES,
  TIMELINE_PRECISION_LABELS,
  TIMELINE_PRECISIONS,
  type TimelineExportFormat,
} from './timelineUtils';

const PNG_SCALE = 2;

const TIMELINE_EXPORT_MIME_TYPES: Record<TimelineExportFormat, string> = {
  pdf: 'application/pdf',
  csv: 'text/csv',
  png: 'image/png',
  svg: 'image/svg+xml',
};

const downloadBlob = (blob: Blob, fileName: string) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Let the browser start the download before releasing the object
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

const svgToPngBlob = (svg: string, width: number, height: number): Promise<Blob> => new Promise((resolve, reject) => {
  const image = new Image();
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }));
  image.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = width * PNG_SCALE;
    canvas.height = height * PNG_SCALE;
    const context = canvas.getContext('2d');
    if (!context) {
      URL.revokeObjectURL(url);
      reject(new Error('Canvas is not available'));
      return;
    }
    context.scale(PNG_SCALE, PNG_SCALE);
    context.drawImage(image, 0, 0, width, height);
    URL.revokeObjectURL(url);
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error('PNG encoding failed'))), 'image/png');
  };
  image.onerror = () => {
    URL.revokeObjectURL(url);
    reject(new Error('SVG rendering failed'));
  };
  image.src = url;
});

type TimelineServerFormat = ContainerTimelineMutationsExportQuery$variables['format'];

// PDF and PNG files are produced in the browser from the HTML and SVG rendered by the server
const serverFormatOf = (format: TimelineExportFormat): TimelineServerFormat => {
  if (format === 'csv') return 'csv';
  if (format === 'pdf') return 'html';
  return 'svg';
};

const serverContentToBlob = async (format: TimelineExportFormat, content: string): Promise<Blob> => {
  if (format === 'csv') {
    return new Blob([content], { type: `${TIMELINE_EXPORT_MIME_TYPES.csv};charset=utf-8` });
  }
  if (format === 'pdf') {
    // Built-in HTML to PDF export, the timeline being rendered server side as an SVG in the HTML
    return htmlToPdf('timeline', fitSvgToWidth(content, MAX_WIDTH_PORTRAIT)).getBlob();
  }
  if (format === 'svg') {
    return new Blob([content], { type: `${TIMELINE_EXPORT_MIME_TYPES.svg};charset=utf-8` });
  }
  const match = content.match(/width="(\d+)" height="(\d+)"/);
  const size = match ? { width: Number(match[1]), height: Number(match[2]) } : { width: 1200, height: 400 };
  return svgToPngBlob(content, size.width, size.height);
};

/** Filters of the exported events, the whole timeline when none is given. */
export interface TimelineExportFilters {
  lanes?: readonly string[] | null;
  kinds?: readonly string[] | null;
  sources?: readonly string[] | null;
  search?: string | null;
  includeHidden?: boolean;
  pinnedOnly?: boolean;
  // Time window (ISO dates) of the events
  from?: string | null;
  to?: string | null;
  // Content ceiling of the export dialog: events marked above it are left out
  contentMaxMarkings?: readonly string[] | null;
}

export interface TimelineFileOptions extends TimelineExportFilters {
  containerId: string;
  format: TimelineExportFormat;
}

/** Renders a timeline export as a file content, from the events the current user can see. */
export const useTimelineFileRenderer = () => {
  const { t_i18n } = useFormatter();

  // Exports are standalone documents: every label the server writes is translated here
  const labels = () => [
    { key: 'title', label: t_i18n('Timeline') },
    { key: 'generated_at', label: t_i18n('Generated at') },
    { key: 'anchors', label: t_i18n('Anchors') },
    { key: 'events', label: t_i18n('Events') },
    { key: 'no_events', label: t_i18n('No event') },
    ...TIMELINE_LANES.map((lane) => ({ key: `lane.${lane}`, label: t_i18n(TIMELINE_LANE_LABELS[lane]) })),
    ...Object.entries(TIMELINE_KIND_LABELS).map(([kind, label]) => ({ key: `kind.${kind}`, label: t_i18n(label) })),
    ...TIMELINE_PRECISIONS.map((precision) => ({ key: `precision.${precision}`, label: t_i18n(TIMELINE_PRECISION_LABELS[precision]) })),
    ...TIMELINE_ANCHOR_KEYS.map((key) => ({ key: `anchor.${key}`, label: t_i18n(TIMELINE_ANCHOR_LABELS[key]) })),
    { key: 'column.time', label: t_i18n('Time') },
    { key: 'column.end_time', label: t_i18n('End time') },
    { key: 'column.lane', label: t_i18n('Lane') },
    { key: 'column.kind', label: t_i18n('Kind') },
    { key: 'column.precision', label: t_i18n('Precision') },
    { key: 'column.title', label: t_i18n('Title') },
    { key: 'column.element', label: t_i18n('Element') },
    { key: 'column.annotation', label: t_i18n('Annotation') },
    { key: 'still_open', label: t_i18n('Still open') },
  ];

  const fetchServerExport = async (options: TimelineFileOptions, format: TimelineServerFormat) => {
    const variables: ContainerTimelineMutationsExportQuery$variables = {
      id: options.containerId,
      format,
      from: options.from ?? null,
      to: options.to ?? null,
      lanes: (options.lanes ?? null) as GqlTimelineLane[] | null,
      kinds: (options.kinds ?? null) as TimelineEventKind[] | null,
      sources: options.sources && options.sources.length > 0 ? options.sources as TimelineEventSource[] : null,
      search: options.search || null,
      includeHidden: options.includeHidden ?? false,
      pinnedOnly: options.pinnedOnly ?? false,
      labels: format === 'csv' ? null : labels(),
      contentMaxMarkings: options.contentMaxMarkings && options.contentMaxMarkings.length > 0 ? [...options.contentMaxMarkings] : null,
    };
    const result = await fetchQuery<ContainerTimelineMutationsExportQuery>(containerTimelineExportQuery, variables, { fetchPolicy: 'network-only' }).toPromise();
    return result?.containerTimelineExport ?? '';
  };

  // Every format comes from the server export snapshot (max shareable markings, content ceiling, anchors of the exported
  // events); PNG is the server SVG rasterized in the browser
  const renderTimelineFile = async (options: TimelineFileOptions): Promise<Blob> => {
    return serverContentToBlob(options.format, await fetchServerExport(options, serverFormatOf(options.format)));
  };

  /**
   * Export stored as a file of the container. The content and its markings come from the same events on the server:
   * the selected markings are raised to cover the exported events and the elements they reference (a file is never
   * marked less strictly than its content). `raised` names the markings added.
   */
  const renderStoredTimelineFile = async (containerId: string, format: TimelineExportFormat, contentMaxMarkings: string[], fileMarkings: string[]) => {
    const serverFormat = serverFormatOf(format);
    const result = await fetchQuery<ContainerTimelineMutationsExportFileQuery>(
      containerTimelineExportFileQuery,
      {
        id: containerId,
        format: serverFormat,
        labels: serverFormat === 'csv' ? null : labels(),
        contentMaxMarkings: contentMaxMarkings.length > 0 ? contentMaxMarkings : null,
        fileMarkings,
      },
      { fetchPolicy: 'network-only' },
    ).toPromise();
    const exported = result?.containerTimelineExportFile;
    if (!exported) throw new Error('Unable to export the timeline');
    const markings = exported.file_markings;
    return {
      blob: await serverContentToBlob(format, exported.content),
      fileMarkings: {
        ids: markings.map((marking) => marking.id),
        raised: markings.filter((marking) => !fileMarkings.includes(marking.id)).map((marking) => marking.definition ?? marking.id),
      },
    };
  };

  return { renderTimelineFile, renderStoredTimelineFile };
};

/** Message of a failed timeline export: one too large to export at once is narrowed with the filters or the window. */
export const timelineExportErrorMessage = (error: unknown, t_i18n: (message: string) => string): string => {
  const errors = (error as Partial<RelayError> | null)?.res?.errors ?? [];
  const tooLarge = errors.some((e) => (e.extensions?.data as { doc_code?: string } | undefined)?.doc_code === 'TIMELINE_EXPORT_TOO_LARGE');
  return tooLarge
    ? t_i18n('This timeline is too large to export at once: narrow the export with the filters or the time window')
    : t_i18n('The timeline export failed');
};

/** Maps an export format of the container export dialog to the timeline format producing it. */
export const timelineFormatOfMimeType = (mimeType: string): TimelineExportFormat | null => {
  const entry = Object.entries(TIMELINE_EXPORT_MIME_TYPES).find(([, mime]) => mime === mimeType);
  return entry ? entry[0] as TimelineExportFormat : null;
};

export const TIMELINE_EXPORT_MIME_TYPE_LIST = Object.values(TIMELINE_EXPORT_MIME_TYPES);

interface TimelineExportOptions {
  containerId: string;
  containerName: string;
  filters: TimelineExportFilters;
}

/** Download of the timeline from the tab toolbar, with the filters and the time window of the current view. */
const useContainerTimelineExport = ({ containerId, containerName, filters }: TimelineExportOptions) => {
  const { t_i18n } = useFormatter();
  const { renderTimelineFile } = useTimelineFileRenderer();
  const [exporting, setExporting] = useState(false);

  const exportTimeline = async (format: TimelineExportFormat) => {
    setExporting(true);
    try {
      const blob = await renderTimelineFile({ containerId, format, ...filters });
      downloadBlob(blob, buildTimelineFileName(containerName, format));
    } catch (error) {
      MESSAGING$.notifyError(timelineExportErrorMessage(error, t_i18n));
    } finally {
      setExporting(false);
    }
  };

  return { exportTimeline, exporting };
};

export default useContainerTimelineExport;
