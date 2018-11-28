import React, {Component} from "react";
import {injectIntl} from "react-intl";

function getDisplayName(Component) {
    return Component.displayName || Component.name || 'Component';
}

export default function inject18n(WrappedComponent) {
    class InjectIntl extends Component {
        static displayName = `i18n(${getDisplayName(WrappedComponent)})`;
        render() {
            const {children} = this.props;
            const translate = (message) => {
                return this.props.intl.formatMessage({id: message})
            };
            return (
                <WrappedComponent{...this.props}{...{'t': translate}}>
                    {children}
                </WrappedComponent>
            );
        }
    }

    return injectIntl(InjectIntl);
}