import { RefObject, useState } from 'react';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { htmlToPdf } from '../../../../utils/htmlToPdf/htmlToPdf';
import { MAX_WIDTH_PORTRAIT } from '../../../../utils/htmlToPdf/utils/constants';
import { containerTimelineExportQuery } from './ContainerTimelineMutations';
import type {
  ContainerTimelineMutationsExportQuery,
  ContainerTimelineMutationsExportQuery$variables,
  TimelineEventKind,
  TimelineLane as GqlTimelineLane,
} from './__generated__/ContainerTimelineMutationsExportQuery.graphql';
import type { TimelineExportFormat } from './ContainerTimelineToolbar';
import {
  buildTimelineFileName,
  fitSvgToWidth,
  serializeSvgElement,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_ANCHOR_LABELS,
  TIMELINE_KIND_LABELS,
  TIMELINE_LANE_LABELS,
  TIMELINE_LANES,
  TIMELINE_PRECISION_LABELS,
  TIMELINE_PRECISIONS,
} from './timelineUtils';

const PNG_SCALE = 2;

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

interface TimelineExportOptions {
  containerId: string;
  containerName: string;
  lanes: readonly string[] | null;
  kinds: readonly string[] | null;
  includeHidden: boolean;
  // The rendered lanes chart, exported as is for SVG and PNG; the server rendering is used otherwise
  svgRef: RefObject<SVGSVGElement | null>;
}

const useContainerTimelineExport = ({ containerId, containerName, lanes, kinds, includeHidden, svgRef }: TimelineExportOptions) => {
  const { t_i18n } = useFormatter();
  const [exporting, setExporting] = useState(false);

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
  ];

  const fetchServerExport = async (format: 'csv' | 'svg' | 'html') => {
    const variables: ContainerTimelineMutationsExportQuery$variables = {
      id: containerId,
      format,
      lanes: lanes as GqlTimelineLane[] | null,
      kinds: kinds as TimelineEventKind[] | null,
      includeHidden,
      labels: format === 'csv' ? null : labels(),
    };
    const result = await fetchQuery<ContainerTimelineMutationsExportQuery>(containerTimelineExportQuery, variables, { fetchPolicy: 'network-only' }).toPromise();
    return result?.containerTimelineExport ?? '';
  };

  const renderedSvg = (): { svg: string; width: number; height: number } | null => {
    const element = svgRef.current;
    if (!element) return null;
    const width = Number(element.getAttribute('width'));
    const height = Number(element.getAttribute('height'));
    return { svg: serializeSvgElement(element), width, height };
  };

  const exportTimeline = async (format: TimelineExportFormat) => {
    setExporting(true);
    try {
      if (format === 'csv') {
        const csv = await fetchServerExport('csv');
        downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), buildTimelineFileName(containerName, 'csv'));
      } else if (format === 'pdf') {
        // Built-in HTML to PDF export, the timeline being rendered server side as an SVG in the HTML
        const html = fitSvgToWidth(await fetchServerExport('html'), MAX_WIDTH_PORTRAIT);
        const fileName = buildTimelineFileName(containerName, 'pdf');
        htmlToPdf(fileName, html).download(fileName);
      } else {
        const rendered = renderedSvg();
        let svg = rendered?.svg;
        let size = rendered ? { width: rendered.width, height: rendered.height } : null;
        if (!svg || !size) {
          svg = await fetchServerExport('svg');
          const match = svg.match(/width="(\d+)" height="(\d+)"/);
          size = match ? { width: Number(match[1]), height: Number(match[2]) } : { width: 1200, height: 400 };
        }
        if (format === 'svg') {
          downloadBlob(new Blob([svg], { type: 'image/svg+xml;charset=utf-8' }), buildTimelineFileName(containerName, 'svg'));
        } else {
          const png = await svgToPngBlob(svg, size.width, size.height);
          downloadBlob(png, buildTimelineFileName(containerName, 'png'));
        }
      }
    } catch {
      MESSAGING$.notifyError(t_i18n('The timeline export failed'));
    } finally {
      setExporting(false);
    }
  };

  return { exportTimeline, exporting };
};

export default useContainerTimelineExport;
