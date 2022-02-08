/* eslint-disable */

const ImportFreshdeskScript = () => {
    const popupScript = document.createElement("script");
    popupScript.innerHTML = `window.fwSettings={
      'widget_id':67000003720
      };
      !function(){if("function"!=typeof window.FreshworksWidget){var n=function(){n.q.push(arguments)};n.q=[],window.FreshworksWidget=n}}()`;

    const embededScript = document.createElement("script");
    embededScript.type = "text/javascript";
    embededScript.src = "https://widget.freshworks.com/widgets/67000003720.js";
    embededScript.async = true;
    embededScript.defer = true;

    document.body.appendChild(popupScript);
    document.body.appendChild(embededScript);
    return () => {
      document.body.removeChild(popupScript);
      document.body.removeChild(embededScript);
    };
};

export default ImportFreshdeskScript;
