export type BuildFileFromTemplateOptions = {
  removeEmptySections?: boolean;
};

export type TemplateVariableResolution = {
  variableName: string;
  replacement: string;
  isEmpty: boolean;
  preserveSection?: boolean;
  replaceAll?: boolean;
};

type TemplateSection = {
  id: number;
  level: number;
  heading: HTMLHeadingElement;
  children: TemplateSection[];
  variableNames: Set<string>;
  ownedNodes: Node[];
  hasVariablesInTree?: boolean;
  shouldKeep?: boolean;
};

const VARIABLE_PATTERN = /\$([A-Za-z0-9_]+)/g;
const MEANINGFUL_MEDIA_SELECTOR = 'img, svg, canvas, video, audio, iframe, object, embed';

const normalizeTextValue = (value: string) => value
  .replace(/[\u200B-\u200D\uFEFF]/g, '')
  .replace(/\u00A0/g, ' ')
  .trim();

const extractVariableNames = (value: string) => {
  return Array.from(value.matchAll(VARIABLE_PATTERN), ([, variableName]) => variableName);
};

const createContainer = (html: string) => {
  const container = document.createElement('div');
  container.innerHTML = html;
  return container;
};

const isSemanticallyEmptyNode = (node: Node): boolean => {
  if (node.nodeType === Node.TEXT_NODE) {
    return normalizeTextValue(node.textContent ?? '') === '';
  }

  if (!(node instanceof Element)) {
    return true;
  }

  if (node.matches(MEANINGFUL_MEDIA_SELECTOR)) {
    return false;
  }

  if (node.querySelector(MEANINGFUL_MEDIA_SELECTOR)) {
    return false;
  }

  return Array.from(node.childNodes).every(isSemanticallyEmptyNode);
};

export const isSemanticallyEmptyHtmlFragment = (value: string) => {
  if (normalizeTextValue(value) === '') {
    return true;
  }

  const container = createContainer(value);
  return Array.from(container.childNodes).every(isSemanticallyEmptyNode);
};

const extractVariableNamesFromNode = (node: Node): string[] => {
  if (node.nodeType === Node.TEXT_NODE) {
    return extractVariableNames(node.textContent ?? '');
  }

  if (!(node instanceof Element)) {
    return [];
  }

  const ownAttributeVariables = Array.from(node.attributes)
    .flatMap((attribute) => extractVariableNames(attribute.value));
  const childVariables = Array.from(node.childNodes)
    .flatMap((childNode) => extractVariableNamesFromNode(childNode));

  return [...ownAttributeVariables, ...childVariables];
};

const hasHeadingDescendant = (node: Node) => node instanceof Element && node.querySelector('h1, h2, h3') !== null;

const addOwnedNode = (section: TemplateSection, node: Node) => {
  section.ownedNodes.push(node);
  extractVariableNamesFromNode(node).forEach((variableName) => {
    section.variableNames.add(variableName);
  });
};

const flattenSections = (sections: TemplateSection[]): TemplateSection[] => {
  return sections.flatMap(function collect(section): TemplateSection[] {
    return [section, ...flattenSections(section.children)];
  });
};

const buildSectionTree = (container: HTMLElement) => {
  const headings = Array.from(container.querySelectorAll('h1, h2, h3')) as HTMLHeadingElement[];
  const rootSections: TemplateSection[] = [];
  const stack: TemplateSection[] = [];
  const sectionsByHeading = new Map<HTMLHeadingElement, TemplateSection>();

  headings.forEach((heading, index) => {
    const level = Number.parseInt(heading.tagName.slice(1), 10);
    while (stack.length > 0 && stack[stack.length - 1].level >= level) {
      stack.pop();
    }

    const section: TemplateSection = {
      id: index,
      level,
      heading,
      children: [],
      variableNames: new Set<string>(),
      ownedNodes: [],
    };

    const parent = stack[stack.length - 1];
    if (parent) {
      parent.children.push(section);
    } else {
      rootSections.push(section);
    }

    stack.push(section);
    sectionsByHeading.set(heading, section);
  });

  const activeSections: TemplateSection[] = [];
  const visitNode = (node: Node) => {
    const section = node instanceof HTMLHeadingElement ? sectionsByHeading.get(node) : undefined;
    if (section) {
      while (activeSections.length > 0 && activeSections[activeSections.length - 1].level >= section.level) {
        activeSections.pop();
      }

      activeSections.push(section);
      addOwnedNode(section, node);
      return;
    }

    if (hasHeadingDescendant(node)) {
      Array.from(node.childNodes).forEach(visitNode);
      return;
    }

    const currentSection = activeSections[activeSections.length - 1];
    if (currentSection) {
      addOwnedNode(currentSection, node);
    }
  };

  Array.from(container.childNodes).forEach(visitNode);
  return rootSections;
};

const decideSectionRetention = (
  section: TemplateSection,
  resolutions: Map<string, TemplateVariableResolution>,
) => {
  const keptChildren = section.children.filter((child) => decideSectionRetention(child, resolutions));
  const variables = Array.from(section.variableNames);
  const hasVariablesInTree = variables.length > 0 || section.children.some((child) => child.hasVariablesInTree);
  const hasPreservedVariable = variables.some((variableName) => {
    const resolution = resolutions.get(variableName);
    return !resolution || resolution.preserveSection || !resolution.isEmpty;
  });
  const shouldKeep = !hasVariablesInTree || hasPreservedVariable || keptChildren.length > 0;

  section.hasVariablesInTree = hasVariablesInTree;
  section.shouldKeep = shouldKeep;
  return shouldKeep;
};

const isRemovableEmptyWrapper = (element: HTMLElement) => {
  return Array.from(element.childNodes).every((childNode) => {
    return childNode.nodeType === Node.TEXT_NODE
      && normalizeTextValue(childNode.textContent ?? '') === '';
  });
};

const getAncestorDepth = (element: HTMLElement, container: HTMLElement) => {
  let depth = 0;
  let candidate: HTMLElement | null = element;
  while (candidate && candidate !== container) {
    depth += 1;
    candidate = candidate.parentElement;
  }
  return depth;
};

const pruneRemovedSectionWrappers = (container: HTMLElement, removedNodes: Node[]) => {
  const ancestors = new Set<HTMLElement>();

  removedNodes.forEach((node) => {
    if (node instanceof HTMLElement && node !== container) {
      ancestors.add(node);
    }

    let candidate = node.parentElement;
    while (candidate && candidate !== container) {
      ancestors.add(candidate);
      candidate = candidate.parentElement;
    }
  });

  Array.from(ancestors)
    .sort((left, right) => getAncestorDepth(right, container) - getAncestorDepth(left, container))
    .forEach((ancestor) => {
      if (ancestor.parentNode && isRemovableEmptyWrapper(ancestor)) {
        ancestor.remove();
      }
    });
};

const replaceTemplateVariables = (templateContent: string, resolutions: Map<string, TemplateVariableResolution>) => {
  return templateContent.replace(VARIABLE_PATTERN, (match, variableName) => {
    return resolutions.get(variableName)?.replacement ?? match;
  });
};

export const buildTemplateContentWithOptionalSectionPruning = (
  templateContent: string,
  resolutions: TemplateVariableResolution[],
  options?: BuildFileFromTemplateOptions,
) => {
  if (!options?.removeEmptySections) {
    return templateContent;
  }

  const resolutionMap = new Map(resolutions.map((resolution) => [resolution.variableName, resolution]));
  const container = createContainer(templateContent);
  const rootSections = buildSectionTree(container);

  rootSections.forEach((section) => {
    decideSectionRetention(section, resolutionMap);
  });

  const removedSections = flattenSections(rootSections)
    .filter((section) => !section.shouldKeep)
    .sort((left, right) => right.level - left.level || right.id - left.id);

  removedSections.forEach((section) => {
    const removableNodes = [...section.ownedNodes].reverse();
    const removableAncestors = removableNodes.flatMap((node) => {
      const ancestors: Node[] = [];
      let candidate = node.parentElement;
      while (candidate && candidate !== container) {
        ancestors.push(candidate);
        candidate = candidate.parentElement;
      }
      return ancestors;
    });

    removableNodes.forEach((node) => {
      if (node.parentNode) {
        node.parentNode.removeChild(node);
      }
    });
    pruneRemovedSectionWrappers(container, removableAncestors);
  });

  return replaceTemplateVariables(container.innerHTML, resolutionMap);
};
