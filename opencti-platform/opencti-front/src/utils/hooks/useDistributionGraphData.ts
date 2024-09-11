import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../components/i18n';
import { getMainRepresentative, isFieldForIdentifier } from '../defaultRepresentatives';
import { itemColor } from '../Colors';
import useAuth from './useAuth';

// common type compatible with all distribution queries
type DistributionNode = {
  readonly label: string,
  readonly value?: number | null,

  readonly entity?: {
    readonly entity_type?: string,
    readonly id?: string,
    // when colors are requested from Labels, Markings or Status for instance
    readonly color?: string | null,
    readonly x_opencti_color?: string | null,
    readonly template?: {
      readonly color?: string | null
    } | null
    // workspaces
    readonly type?: string,
  } | null,
};

export type DistributionQueryData = ReadonlyArray<DistributionNode | null | undefined>;

type Selection = {
  attribute?: string,
  label?: string,
};

const useDistributionGraphData = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const { me: { monochrome_labels } } = useAuth();

  const getColorFromDistributionNode = (n: DistributionNode, selection: Selection) => {
    let color = isFieldForIdentifier(selection.attribute)
      ? itemColor(n.entity?.entity_type ?? '', dark, undefined, monochrome_labels ?? false)
      : itemColor(n.label, dark, undefined, monochrome_labels ?? false);
    if (n.entity?.color) {
      color = theme.palette.mode === 'light' && n.entity.color === '#ffffff'
        ? '#000000'
        : n.entity.color;
    }
    if (n.entity?.x_opencti_color) {
      color = theme.palette.mode === 'light'
      && n.entity.x_opencti_color === '#ffffff'
        ? '#000000'
        : n.entity.x_opencti_color;
    }
    if (n.entity?.template?.color) {
      color = theme.palette.mode === 'light'
      && n.entity.template.color === '#ffffff'
        ? '#000000'
        : n.entity.template.color;
    }

    return color;
  };

  const buildDistributionGraphData = (distributionData: DistributionQueryData, selection: Selection) => {
    return distributionData.map((n) => {
      if (!n) return { x: 'Unknown', y: 'Unknown' };
      let { label } = n;
      if (isFieldForIdentifier(selection.attribute)) {
        label = getMainRepresentative(n.entity) || n.label;
      } else if (selection.attribute === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`) {
        label = t_i18n(`entity_${n.label}`);
      }
      return {
        x: label,
        y: n.value,
        fillColor: getColorFromDistributionNode(n, selection),
      };
    });
  };

  const buildDistributionRedirectionUtils = (distributionData: DistributionQueryData) => {
    return distributionData.flatMap((n) => {
      if (!n || !n.entity || !n.entity.id) return [];
      return {
        id: n.entity.id,
        entity_type: n.entity?.entity_type === 'Workspace' ? n.entity.type : n.entity.entity_type,
      };
    });
  };

  /**
   * Conveniently build the series (chart data) and redirectionUtils props for a Widget
   * from the distribution query results and the selection config.
   * @param distributionData
   * @param selection
   * @param defaultGraphLabel
   */
  const buildWidgetProps = (distributionData: DistributionQueryData, selection: Selection, defaultGraphLabel: string) => {
    return {
      series: [{
        name: selection.label || t_i18n(defaultGraphLabel),
        data: buildDistributionGraphData(distributionData, selection),
      }],
      redirectionUtils: buildDistributionRedirectionUtils(distributionData),
    };
  };

  /**
   * Build from query data the labels to use in the graph.
   * @param distributionData
   * @param groupBy
   */
  const buildWidgetLabelsOption = (distributionData: DistributionQueryData, groupBy: string) => {
    return distributionData.map((n) => {
      if (!n) return 'Unknown';
      if (isFieldForIdentifier(groupBy)) {
        return getMainRepresentative(n.entity);
      }
      if (groupBy === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`) {
        return t_i18n(`entity_${n.label}`);
      }
      return n.label;
    });
  };

  const buildWidgetColorsOptions = (distributionData: DistributionQueryData, groupBy: string) => {
    if (
      !distributionData.at(0)?.entity?.color
      && !distributionData.at(0)?.entity?.x_opencti_color
      && !distributionData.at(0)?.entity?.template?.color
    ) {
      return [];
    }
    return distributionData.map((n) => {
      if (!n) return '#000000';
      return getColorFromDistributionNode(n, { attribute: groupBy });
    });
  };

  return {
    buildWidgetProps,
    buildWidgetLabelsOption,
    buildWidgetColorsOptions,
  };
};

export default useDistributionGraphData;
