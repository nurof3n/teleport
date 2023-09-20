/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import { Node, AwsMetadata } from './types';

export default function makeNode(json: any): Node {
  json = json ?? {};
  const { id, siteId, subKind, hostname, addr, tunnel, tags, sshLogins, aws } =
    json;

  return {
    kind: 'node',
    id,
    subKind: formatSubKindInfo(subKind),
    clusterId: siteId,
    hostname,
    labels: tags ?? [],
    addr,
    tunnel,
    sshLogins: sshLogins ?? [],
    awsMetadata: aws ? makeAwsMetadata(aws) : undefined,
  };
}

function makeAwsMetadata(json: any): AwsMetadata {
  json = json ?? {};
  const { accountId, instanceId, region, vpcId, integration, subnetId } = json;

  return {
    accountId,
    instanceId,
    region,
    vpcId,
    integration,
    subnetId,
  };
}

function formatSubKindInfo(subKind: string) {
  switch (subKind) {
    case 'openssh-ec2-ice':
    case 'openssh':
      return 'OpenSSH Server';

    default:
      return 'SSH Server';
  }
}
