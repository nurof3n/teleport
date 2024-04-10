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

import { useEffect, useState } from 'react';
import useAttempt from 'shared/hooks/useAttemptNext';

import { Resource } from 'teleport/services/resources';
import useTeleport from 'teleport/useTeleport';

export default function useAuthConnectors() {
  const ctx = useTeleport();
  const [items, setItems] = useState<Resource<'github'>[]>([]);
  const [itemsOidc, setItemsOidc] = useState<Resource<'oidc'>[]>([]);
  const { attempt, run } = useAttempt('processing');

  function fetchData() {
    return Promise.all([
      ctx.resourceService.fetchGithubConnectors().then(response => {
        setItems(response);
      }),
      ctx.resourceService.fetchOidcConnectors().then(response => {
        setItemsOidc(response);
      }),
    ]);
  }

  function save(name: string, yaml: string, isNew: boolean) {
    if (isNew) {
      return ctx.resourceService.createGithubConnector(yaml).then(fetchData);
    }
    return ctx.resourceService
      .updateGithubConnector(name, yaml)
      .then(fetchData);
  }

  function saveOidc(name: string, yaml: string, isNew: boolean) {
    if (isNew) {
      return ctx.resourceService.createOidcConnector(yaml).then(fetchData);
    }
    return ctx.resourceService.updateOidcConnector(name, yaml).then(fetchData);
  }

  function remove(name: string) {
    return ctx.resourceService.deleteGithubConnector(name).then(fetchData);
  }

  function removeOidc(name: string) {
    return ctx.resourceService.deleteOidcConnector(name).then(fetchData);
  }

  useEffect(() => {
    run(() => fetchData());
  }, []);

  return {
    items,
    itemsOidc,
    attempt,
    save,
    saveOidc,
    remove,
    removeOidc,
  };
}

export type State = ReturnType<typeof useAuthConnectors>;
