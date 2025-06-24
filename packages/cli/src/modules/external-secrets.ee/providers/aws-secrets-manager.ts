import { SecretsManager, type SecretsManagerClientConfig } from '@aws-sdk/client-secrets-manager';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { Logger } from '@n8n/backend-common';
import { Container } from '@n8n/di';
import type { INodeProperties } from 'n8n-workflow';

import { DOCS_HELP_NOTICE, EXTERNAL_SECRETS_NAME_REGEX } from '../constants';
import { UnknownAuthTypeError } from '../errors/unknown-auth-type.error';
import type { SecretsProvider, SecretsProviderSettings, SecretsProviderState } from '../types';

type Secret = {
	secretName: string;
	secretValue: string;
};

export type AwsSecretsManagerContext = SecretsProviderSettings<
	{
		region: string;
		// Optional STS configuration for cross-account access
		stsRoleArn?: string;
		stsExternalId?: string;
		stsSessionName?: string;
	} & (
		| {
				authMethod: 'iamUser';
				accessKeyId: string;
				secretAccessKey: string;
		  }
		| { authMethod: 'autoDetect' }
	)
>;

export class AwsSecretsManager implements SecretsProvider {
	name = 'awsSecretsManager';

	displayName = 'AWS Secrets Manager';

	state: SecretsProviderState = 'initializing';

	properties: INodeProperties[] = [
		DOCS_HELP_NOTICE,
		{
			displayName: 'Region',
			name: 'region',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. eu-west-3',
			noDataExpression: true,
		},
		{
			displayName: 'Authentication Method',
			name: 'authMethod',
			type: 'options',
			options: [
				{
					name: 'IAM User',
					value: 'iamUser',
					description:
						'Credentials for IAM user having <code>secretsmanager:ListSecrets</code> and <code>secretsmanager:BatchGetSecretValue</code> permissions. <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html" target="_blank">Learn more</a>',
				},
				{
					name: 'Auto Detect',
					value: 'autoDetect',
					description:
						'Use automatic credential detection to authenticate AWS calls for external secrets<a href="https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/setting-credentials-node.html#credchain" target="_blank">Learn more</a>.',
				},
			],
			default: 'iamUser',
			required: true,
			noDataExpression: true,
		},
		{
			displayName: 'Access Key ID',
			name: 'accessKeyId',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. ACHXUQMBAQEVTE2RKMWP',
			noDataExpression: true,
			displayOptions: {
				show: {
					authMethod: ['iamUser'],
				},
			},
		},
		{
			displayName: 'Secret Access Key',
			name: 'secretAccessKey',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. cbmjrH/xNAjPwlQR3i/1HRSDD+esQX/Lan3gcmBc',
			typeOptions: { password: true },
			noDataExpression: true,
			displayOptions: {
				show: {
					authMethod: ['iamUser'],
				},
			},
		},
		{
			displayName: 'Cross-Account Access',
			name: 'crossAccountNotice',
			type: 'notice',
			default: '',
			displayOptions: {
				show: {},
			},
			typeOptions: {
				theme: 'info',
			},
			description:
				'Configure STS role assumption for cross-account access to AWS Secrets Manager. Leave empty to use same-account access.',
		},
		{
			displayName: 'STS Role ARN',
			name: 'stsRoleArn',
			type: 'string',
			default: '',
			placeholder: 'e.g. arn:aws:iam::123456789012:role/CrossAccountSecretsRole',
			description: 'ARN of the IAM role to assume for cross-account access',
			noDataExpression: true,
		},
		{
			displayName: 'STS External ID',
			name: 'stsExternalId',
			type: 'string',
			default: '',
			placeholder: 'e.g. unique-external-id-123',
			description:
				'External ID for additional security when assuming the role (optional but recommended)',
			noDataExpression: true,
		},
		{
			displayName: 'STS Session Name',
			name: 'stsSessionName',
			type: 'string',
			default: 'n8n-external-secrets',
			placeholder: 'e.g. n8n-external-secrets',
			description: 'Name for the assumed role session (optional)',
			noDataExpression: true,
		},
	];

	private cachedSecrets: Record<string, string> = {};

	private client: SecretsManager;

	constructor(private readonly logger = Container.get(Logger)) {
		this.logger = this.logger.scoped('external-secrets');
	}

	async init(context: AwsSecretsManagerContext) {
		this.assertAuthType(context);

		const { region, authMethod, stsRoleArn } = context.settings;
		const clientConfig: SecretsManagerClientConfig = { region };

		// If STS role is configured, assume the role for cross-account access
		if (stsRoleArn) {
			const stsCredentials = await this.assumeRole(context);
			clientConfig.credentials = stsCredentials;
		} else if (authMethod === 'iamUser') {
			const { accessKeyId, secretAccessKey } = context.settings;
			clientConfig.credentials = { accessKeyId, secretAccessKey };
		}
		// For autoDetect, credentials will be automatically detected by AWS SDK

		this.client = new SecretsManager(clientConfig);

		this.logger.debug('AWS Secrets Manager provider initialized');
	}

	async test(): Promise<[boolean] | [boolean, string]> {
		try {
			await this.client.listSecrets({ MaxResults: 1 });
			return [true];
		} catch (e) {
			const error = e instanceof Error ? e : new Error(`${e}`);
			return [false, error.message];
		}
	}

	async connect() {
		const [wasSuccessful, errorMsg] = await this.test();

		this.state = wasSuccessful ? 'connected' : 'error';

		if (wasSuccessful) {
			this.logger.debug('AWS Secrets Manager provider connected');
		} else {
			this.logger.error('AWS Secrets Manager provider failed to connect', { errorMsg });
		}
	}

	async disconnect() {
		return;
	}

	async update() {
		const secrets = await this.fetchAllSecrets();

		const supportedSecrets = secrets.filter((s) => EXTERNAL_SECRETS_NAME_REGEX.test(s.secretName));

		this.cachedSecrets = Object.fromEntries(
			supportedSecrets.map((s) => [s.secretName, s.secretValue]),
		);

		this.logger.debug('AWS Secrets Manager provider secrets updated');
	}

	getSecret(name: string) {
		return this.cachedSecrets[name];
	}

	hasSecret(name: string) {
		return name in this.cachedSecrets;
	}

	getSecretNames() {
		return Object.keys(this.cachedSecrets);
	}

	private assertAuthType(context: AwsSecretsManagerContext) {
		const { authMethod } = context.settings;
		if (authMethod === 'iamUser' || authMethod === 'autoDetect') return;
		throw new UnknownAuthTypeError(authMethod);
	}

	private async assumeRole(context: AwsSecretsManagerContext) {
		const { region, authMethod, stsRoleArn, stsExternalId, stsSessionName } = context.settings;

		// Create STS client with base credentials
		const stsClientConfig: { region: string; credentials?: any } = { region };

		if (authMethod === 'iamUser') {
			const { accessKeyId, secretAccessKey } = context.settings;
			stsClientConfig.credentials = { accessKeyId, secretAccessKey };
		}
		// For autoDetect, let AWS SDK handle credential detection

		const stsClient = new STSClient(stsClientConfig);

		// Prepare assume role parameters
		const assumeRoleParams: any = {
			RoleArn: stsRoleArn,
			RoleSessionName: stsSessionName || 'n8n-external-secrets',
		};

		if (stsExternalId) {
			assumeRoleParams.ExternalId = stsExternalId;
		}

		try {
			const command = new AssumeRoleCommand(assumeRoleParams);
			const response = await stsClient.send(command);

			if (!response.Credentials) {
				throw new Error('Failed to assume role: No credentials returned');
			}

			return {
				accessKeyId: response.Credentials.AccessKeyId!,
				secretAccessKey: response.Credentials.SecretAccessKey!,
				sessionToken: response.Credentials.SessionToken!,
			};
		} catch (error) {
			this.logger.error('Failed to assume STS role', { error, roleArn: stsRoleArn });
			throw error;
		}
	}

	private async fetchAllSecretsNames() {
		const names: string[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.client.listSecrets({
				NextToken: nextToken,
			});

			if (response.SecretList) {
				names.push(...response.SecretList.filter((s) => s.Name).map((s) => s.Name!));
			}

			nextToken = response.NextToken;
		} while (nextToken);

		return names;
	}

	private async fetchAllSecrets() {
		const secrets: Secret[] = [];
		const secretNames = await this.fetchAllSecretsNames();

		// Batch the requests to avoid hitting limits
		const batches = this.batch(secretNames);

		for (const batch of batches) {
			const response = await this.client.batchGetSecretValue({
				SecretIdList: batch,
			});

			if (response.SecretValues) {
				for (const secret of response.SecretValues) {
					if (secret.Name && secret.SecretString) {
						secrets.push({
							secretName: secret.Name,
							secretValue: secret.SecretString,
						});
					}
				}
			}
		}

		return secrets;
	}

	private batch<T>(arr: T[], size = 20): T[][] {
		return Array.from({ length: Math.ceil(arr.length / size) }, (_, index) =>
			arr.slice(index * size, (index + 1) * size),
		);
	}
}
