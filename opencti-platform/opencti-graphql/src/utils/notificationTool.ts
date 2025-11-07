import { marked } from 'marked';

const notificationTool = {
  markdownToHtml: (markdownText?: string) : string | undefined => {
    if (!markdownText) return undefined;
    return marked(markdownText) as string;
  }
};

export default notificationTool;
