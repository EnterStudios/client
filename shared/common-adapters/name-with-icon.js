// @flow
import * as React from 'react'
import Avatar, {type AvatarSize} from './avatar'
import Box from './box'
import Icon from './icon'
import {type IconType} from './icon.constants'
import Text from './text'
import {Usernames} from './usernames'
import {globalStyles, isMobile} from '../styles'

type Size = 'small' | 'default' | 'large'

type Props = {
  following?: boolean,
  followsMe?: boolean,
  horizontal?: boolean,
  icon?: IconType,
  title?: string, // for non-users
  metaOne?: string | React.Node,
  metaTwo?: string | React.Node,
  onClick?: () => void,
  size?: Size,
  containerStyle?: any,
  metaStyle?: any,
  iconStyle?: any,
  isYou?: boolean,
  teamname?: string,
  username?: string,
}

const NameWithIconVertical = (props: Props) => {
  const isAvatar = !!(props.username || props.teamname)
  const isIcon = !isAvatar && !!props.icon
  const isUser = !!props.username
  const adapterProps = getAdapterProps(props.size || 'default', props.horizontal, isAvatar)
  return (
    <Box style={{...containerStyle, ...props.containerStyle}}>
      {isAvatar && (
        <Avatar
          size={adapterProps.iconSize}
          following={props.following}
          followsYou={props.followsMe}
          username={props.username}
          teamname={props.teamname}
        />
      )}
      {isIcon && (
        <Icon
          type={props.icon}
          style={{
            fontSize: adapterProps.iconSize,
            width: adapterProps.iconSize,
            height: adapterProps.iconSize,
          }}
        />
      )}
      <Box style={{...metaStyle, ...props.metaStyle}}>
        {!isUser && <Text type={adapterProps.titleType}>{props.title}</Text>}
        {isUser && (
          <Usernames
            type={adapterProps.titleType}
            users={[{username: props.username, following: props.following, you: props.isYou}]}
            colorFollowing={props.hasOwnProperty('following')}
          />
        )}
        {props.metaOne && <Text type={adapterProps.metaOneType}>{props.metaOne}</Text>}
        {props.metaTwo && <Text type="BodySmall">{props.metaTwo}</Text>}
      </Box>
    </Box>
  )
}

const NameWithIconHorizontal = (props: Props) => {
  const isAvatar = !!(props.username || props.teamname)
  const isIcon = !isAvatar && !!props.icon
  const isUser = !!props.username
  const commonHeight = isMobile ? 48 : 32
  return (
    <Box style={{...globalStyles.flexBoxRow, ...props.containerStyle}}>
      {isAvatar && (
        <Avatar
          size={commonHeight}
          username={props.username}
          teamname={props.teamname}
          style={{marginRight: 16}}
        />
      )}
      {isIcon && (
        <Icon
          type={props.icon}
          style={{marginRight: 16, fontSize: commonHeight, width: commonHeight, height: commonHeight}}
        />
      )}
      <Box style={{...globalStyles.flexBoxColumn, height: commonHeight, ...props.metaStyle}}>
        {!isUser && <Text type="BodySemibold">{props.title}</Text>}
        {isUser && (
          <Usernames
            type="BodySemibold"
            users={[{username: props.username, following: props.following, you: props.isYou}]}
            colorFollowing={props.hasOwnProperty('following')}
          />
        )}
        <Text type="BodySmall">
          {props.metaOne} {props.metaTwo && '·'} {props.metaTwo}
        </Text>
      </Box>
    </Box>
  )
}

const NameWithIcon = (props: Props) => {
  if (props.username && props.teamname) {
    throw new Error('Can onlt use username or teamname in NameWithIcon; got both')
  }
  return props.horizontal ? <NameWithIconHorizontal {...props} /> : <NameWithIconVertical {...props} />
}

const containerStyle = {
  ...globalStyles.flexBoxColumn,
  ...globalStyles.flexBoxCenter,
  padding: 24,
}

const metaStyle = {
  ...globalStyles.flexBoxColumn,
  ...globalStyles.flexBoxCenter,
  marginTop: 8,
}

// Get props to pass to subcomponents (Text, Avatar, etc.)
const getAdapterProps = (size: Size, horizontal: boolean, isAvatar: boolean) => {
  if (horizontal) {
    return {
      titleType: 'BodySemibold',
      metaOneType: 'BodySmall',
      iconSize: isMobile ? 48 : 32,
    }
  }
  switch (size) {
    case 'small':
      return {
        titleType: 'BodySemibold',
        metaOneType: 'BodySmall',
        iconSize: isAvatar ? 64 : 48,
      }
    case 'large':
      if (isAvatar) {
        return {
          titleType: 'HeaderBig',
          metaOneType: 'BodySemibold',
          iconSize: 112,
        }
      } else {
        // Non-avatar has no large case; fallthrough
      }
    default:
      return {
        titleType: 'BodyBig',
        metaOneType: isAvatar ? 'BodySemibold' : 'BodySmall',
        iconSize: isAvatar ? 80 : 64,
      }
  }
}

export default NameWithIcon
export type {Props}
