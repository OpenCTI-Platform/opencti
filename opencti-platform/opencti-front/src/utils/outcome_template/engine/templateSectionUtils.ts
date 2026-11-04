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

const MEANINGFUL_MEDIA_SELECTOR = 'img, svg, canvas, video, audio, iframe, object, embed';

const normalizeTextValue = (value: string) => value
  .replace(/[\u200B-\u200D\uFEFF]/g, '')
  .replace(/\u00A0/g, ' ')
  .trim();

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Only names declared by the template widgets are variables; any other `$word` is prose.
// Longest names first, so `$foo-bar` resolves to `foo-bar` when declared and `$first-$last` splits on the hyphen.
const buildVariablePattern = (variableNames: Iterable<string>) => {
  const alternatives = Array.from(new Set(variableNames))
    .filter((variableName) => variableName.length > 0)
    .sort((left, right) => right.length - left.length)
    .map(escapeRegExp);
  return alternatives.length > 0 ? new RegExp(`\\$(${alternatives.join('|')})`, 'g') : null;
};

const extractVariableNames = (value: string, variablePattern: RegExp | null) => {
  if (!variablePattern) {
    return [];
  }
  return Array.from(value.matchAll(variablePattern), ([, variableName]) => variableName);
};

// Parse in a document without browsing context: unlike the live document, it never fetches
// resources nor runs inline event handlers (e.g. `<img onerror>`) of unsanitized values.
export const parseHtmlInInertDocument = (html: string) => {
  const inertDocument = document.implementation.createHTMLDocument('');
  inertDocument.body.innerHTML = html;
  return inertDocument.body;
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

  const container = parseHtmlInInertDocument(value);
  return Array.from(container.childNodes).every(isSemanticallyEmptyNode);
};

const extractVariableNamesFromNode = (node: Node, variablePattern: RegExp | null): string[] => {
  if (node.nodeType === Node.TEXT_NODE) {
    return extractVariableNames(node.textContent ?? '', variablePattern);
  }

  if (!(node instanceof Element)) {
    return [];
  }

  const ownAttributeVariables = Array.from(node.attributes)
    .flatMap((attribute) => extractVariableNames(attribute.value, variablePattern));
  const childVariables = Array.from(node.childNodes)
    .flatMap((childNode) => extractVariableNamesFromNode(childNode, variablePattern));

  return [...ownAttributeVariables, ...childVariables];
};

const hasHeadingDescendant = (node: Node) => node instanceof Element && node.querySelector('h1, h2, h3') !== null;

const addOwnedNode = (section: TemplateSection, node: Node, variablePattern: RegExp | null) => {
  section.ownedNodes.push(node);
  extractVariableNamesFromNode(node, variablePattern).forEach((variableName) => {
    section.variableNames.add(variableName);
  });
};

const flattenSections = (sections: TemplateSection[]): TemplateSection[] => {
  return sections.flatMap(function collect(section): TemplateSection[] {
    return [section, ...flattenSections(section.children)];
  });
};

const buildSectionTree = (container: HTMLElement, variablePattern: RegExp | null) => {
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
      addOwnedNode(section, node, variablePattern);
      return;
    }

    if (hasHeadingDescendant(node)) {
      Array.from(node.childNodes).forEach(visitNode);
      return;
    }

    const currentSection = activeSections[activeSections.length - 1];
    if (currentSection) {
      addOwnedNode(currentSection, node, variablePattern);
    }
  };

  Array.from(container.childNodes).forEach(visitNode);
  return rootSections;
};

const decideSectionRetention = (
  section: TemplateSection,
  resolutions: Map<string, TemplateVariableResolution>,
): boolean => {
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

const isPageBreak = (node: Node) => node instanceof Element && node.classList.contains('page-break');

// Page breaks followed by no content print a blank last page.
const findTrailingPageBreaks = (container: HTMLElement) => {
  const trailingPageBreaks: Element[] = [];
  const walker = container.ownerDocument.createTreeWalker(container, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      if (node.parentElement?.closest('.page-break')) {
        return NodeFilter.FILTER_REJECT; // A page break's own content (e.g. a hidden `&nbsp;`) is not document content.
      }
      const isContent = node.nodeType === Node.TEXT_NODE
        ? normalizeTextValue(node.textContent ?? '') !== ''
        : (node as Element).matches(MEANINGFUL_MEDIA_SELECTOR);
      return isPageBreak(node) || isContent ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
    },
  });

  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (isPageBreak(node)) {
      trailingPageBreaks.push(node as Element);
    } else {
      trailingPageBreaks.length = 0;
    }
  }

  return trailingPageBreaks;
};

// Same substitution as the legacy path: replaceAll resolutions replace every occurrence, others only the first one.
const replaceTemplateVariables = (
  templateContent: string,
  resolutions: Map<string, TemplateVariableResolution>,
  variablePattern: RegExp | null,
) => {
  if (!variablePattern) {
    return templateContent;
  }

  const replacedVariableNames = new Set<string>();
  return templateContent.replace(variablePattern, (match, variableName: string) => {
    const resolution = resolutions.get(variableName);
    if (!resolution || (!resolution.replaceAll && replacedVariableNames.has(variableName))) {
      return match;
    }
    replacedVariableNames.add(variableName);
    return resolution.replacement;
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
  const variablePattern = buildVariablePattern(resolutionMap.keys());
  const container = parseHtmlInInertDocument(templateContent);
  const rootSections = buildSectionTree(container, variablePattern);
  const initialTrailingPageBreaks = new Set(findTrailingPageBreaks(container));

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

  if (removedSections.length > 0) {
    findTrailingPageBreaks(container)
      .filter((pageBreak) => !initialTrailingPageBreaks.has(pageBreak))
      .forEach((pageBreak) => {
        const { parentElement } = pageBreak;
        pageBreak.remove();
        if (parentElement instanceof HTMLElement && parentElement !== container) {
          pruneRemovedSectionWrappers(container, [parentElement]);
        }
      });
  }

  return replaceTemplateVariables(container.innerHTML, resolutionMap, variablePattern);
};
