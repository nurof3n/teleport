/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';
import { Alert, Box, Flex, Indicator, Link, Text } from 'design';

import { FeatureBox, FeatureHeaderTitle } from 'teleport/components/Layout';
import ResourceEditor from 'teleport/components/ResourceEditor';
import useResources from 'teleport/components/useResources';

import {
  DesktopDescription,
  MobileDescription,
  ResponsiveAddButton,
  ResponsiveFeatureHeader,
} from 'teleport/AuthConnectors/styles/AuthConnectors.styles';

import { Kind, Resource } from 'teleport/services/resources';

import templates from './templates';
import EmptyList from './EmptyList';
import ConnectorList from './ConnectorList';
import DeleteConnectorDialog from './DeleteConnectorDialog';
import useAuthConnectors, { State } from './useAuthConnectors';

export function AuthConnectorsContainer() {
  const state = useAuthConnectors();
  return <AuthConnectors {...state} />;
}

export function AuthConnectors(props: State) {
  const { items, itemsOidc, attempt, save, saveOidc, remove, removeOidc } =
    props;
  const allItems: Resource<Kind>[] = [...items, ...itemsOidc];
  const isEmpty = allItems.length === 0;
  const resources = useResources(allItems, templates);

  const title =
    resources.status === 'creating'
      ? 'Creating a new connector'
      : 'Editing connector';
  const description =
    'Auth connectors allow Teleport to authenticate users via an external identity source such as Okta, Active Directory, GitHub, etc. This authentication method is commonly known as single sign-on (SSO).';

  function handleOnSave(content: string) {
    const name = resources.item.name;
    const isNew = resources.status === 'creating';
    switch (resources.item.kind) {
      case 'github':
        return save(name, content, isNew);
      case 'oidc':
        return saveOidc(name, content, isNew);
    }
    return Promise.reject('Unknown connector type');
  }

  function handleRemove(item: Resource<Kind>) {
    switch (item.kind) {
      case 'github':
        return remove(item.name);
      case 'oidc':
        return removeOidc(item.name);
    }
    return Promise.reject('Unknown connector type');
  }

  return (
    <FeatureBox>
      <ResponsiveFeatureHeader>
        <FeatureHeaderTitle>Auth Connectors</FeatureHeaderTitle>
        <MobileDescription typography="subtitle1">
          {description}
        </MobileDescription>
        <ResponsiveAddButton onClick={() => resources.create('github')}>
          New GitHub Connector
        </ResponsiveAddButton>
        <ResponsiveAddButton onClick={() => resources.create('oidc')}>
          New Oidc Connector
        </ResponsiveAddButton>
      </ResponsiveFeatureHeader>
      {attempt.status === 'failed' && <Alert children={attempt.statusText} />}
      {attempt.status === 'processing' && (
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      )}
      {attempt.status === 'success' && (
        <Flex alignItems="start">
          {isEmpty && (
            <Flex width="100%" justifyContent="center">
              <EmptyList
                onCreate={() => resources.create('github')}
                onCreateOidc={() => resources.create('oidc')}
              />
            </Flex>
          )}
          <>
            <ConnectorList
              items={items}
              onEdit={resources.edit}
              onDelete={resources.remove}
            />
            <DesktopDescription>
              <Text typography="h6" mb={3} caps>
                Auth Connectors
              </Text>
              <Text typography="subtitle1" mb={3}>
                {description}
              </Text>
              <Text typography="subtitle1" mb={2}>
                Please{' '}
                <Link
                  color="text.main"
                  // This URL is the OSS documentation for auth connectors
                  href="https://goteleport.com/docs/access-controls/sso/"
                  target="_blank"
                >
                  view our documentation
                </Link>{' '}
                on how to configure a SSO connector.
              </Text>
            </DesktopDescription>
          </>
        </Flex>
      )}
      {(resources.status === 'creating' || resources.status === 'editing') && (
        <ResourceEditor
          title={title}
          onSave={handleOnSave}
          text={resources.item.content}
          name={resources.item.name}
          isNew={resources.status === 'creating'}
          onClose={resources.disregard}
        />
      )}
      {resources.status === 'removing' && (
        <DeleteConnectorDialog
          name={resources.item.name}
          onClose={resources.disregard}
          onDelete={() => handleRemove(resources.item)}
        />
      )}
    </FeatureBox>
  );
}
