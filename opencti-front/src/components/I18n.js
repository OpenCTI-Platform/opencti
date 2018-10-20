import React from 'react'
import {FormattedMessage, FormattedDate} from 'react-intl'

export const T = (props) => {
    const id = props.children.replace(/(:(\w+))/g, "{$2}")
    return (<FormattedMessage id={id} defaultMessage={id} values={props}/>)
}

export const D = (props) => {
    return (
        <FormattedDate
            value={props.children}
            year='numeric'
            month={props.month}
            day='numeric'
        />
    )
}