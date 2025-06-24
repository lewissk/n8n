import { SecretsManager } from '@aws-sdk/client-secrets-manager';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { mock } from 'jest-mock-extended';

import { AwsSecretsManager, type AwsSecretsManagerContext } from '../aws-secrets-manager';

jest.mock('@aws-sdk/client-secrets-manager');
jest.mock('@aws-sdk/client-sts');

describe('AwsSecretsManager', () => {
	const region = 'eu-central-1';
	const accessKeyId = 'FAKE-ACCESS-KEY-ID';
	const secretAccessKey = 'FAKE-SECRET';

	const context = mock<AwsSecretsManagerContext>();
	const listSecretsSpy = jest.spyOn(SecretsManager.prototype, 'listSecrets');
	const batchGetSpy = jest.spyOn(SecretsManager.prototype, 'batchGetSecretValue');

	let awsSecretsManager: AwsSecretsManager;

	beforeEach(() => {
		jest.resetAllMocks();

		awsSecretsManager = new AwsSecretsManager();
	});

	describe('IAM User authentication', () => {
		it('should fail to connect with invalid credentials', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId: 'invalid',
				secretAccessKey: 'invalid',
			};

			await awsSecretsManager.init(context);

			listSecretsSpy.mockImplementation(() => {
				throw new Error('Invalid credentials');
			});

			await awsSecretsManager.connect();

			expect(awsSecretsManager.state).toBe('error');
		});
	});

	it('should update cached secrets', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};

		await awsSecretsManager.init(context);

		listSecretsSpy.mockImplementation(async () => {
			return {
				SecretList: [{ Name: 'secret1' }, { Name: 'secret2' }],
			};
		});

		batchGetSpy.mockImplementation(async () => {
			return {
				SecretValues: [
					{ Name: 'secret1', SecretString: 'value1' },
					{ Name: 'secret2', SecretString: 'value2' },
				],
			};
		});

		await awsSecretsManager.update();

		expect(listSecretsSpy).toHaveBeenCalledTimes(1);
		expect(batchGetSpy).toHaveBeenCalledWith({
			SecretIdList: expect.arrayContaining(['secret1', 'secret2']),
		});

		expect(awsSecretsManager.getSecret('secret1')).toBe('value1');
		expect(awsSecretsManager.getSecret('secret2')).toBe('value2');
	});

	it('should properly batch secret requests', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};
		await awsSecretsManager.init(context);

		// Generate 25 secrets to test batching (default batch size is 20)
		const secretsList = Array(25)
			.fill(0)
			.map((_, i) => ({ Name: `secret${i}` }));

		listSecretsSpy.mockImplementation(async () => {
			return { SecretList: secretsList };
		});

		batchGetSpy.mockImplementation(async (params) => {
			const secretValues = (params.SecretIdList || []).map((secretId) => ({
				Name: secretId,
				SecretString: `${secretId}-value`,
			}));
			return { SecretValues: secretValues };
		});

		await awsSecretsManager.update();

		// Should have been called twice for 25 secrets with batch size 20
		expect(batchGetSpy).toHaveBeenCalledTimes(2);

		// First batch should have 20 secrets
		expect(batchGetSpy.mock.calls[0][0].SecretIdList?.length).toBe(20);

		// Second batch should have 5 secrets
		expect(batchGetSpy.mock.calls[1][0].SecretIdList?.length).toBe(5);

		// Check a few secrets
		expect(awsSecretsManager.getSecret('secret0')).toBe('secret0-value');
		expect(awsSecretsManager.getSecret('secret24')).toBe('secret24-value');
	});

	it('should handle pagination in listing secrets', async () => {
		context.settings = {
			region,
			authMethod: 'iamUser',
			accessKeyId,
			secretAccessKey,
		};
		await awsSecretsManager.init(context);

		// First call with NextToken
		listSecretsSpy.mockImplementationOnce(async () => {
			return {
				SecretList: [{ Name: 'secret1' }, { Name: 'secret2' }],
				NextToken: 'next-page-token',
			};
		});

		// Second call with no NextToken
		listSecretsSpy.mockImplementationOnce(async () => {
			return {
				SecretList: [{ Name: 'secret3' }],
			};
		});

		batchGetSpy.mockImplementation(async (params) => {
			const secretValues = [];
			for (const secretId of params.SecretIdList || []) {
				secretValues.push({
					Name: secretId,
					SecretString: `${secretId}-value`,
				});
			}
			return { SecretValues: secretValues };
		});

		await awsSecretsManager.update();

		expect(listSecretsSpy).toHaveBeenCalledWith({ NextToken: 'next-page-token' });
		expect(listSecretsSpy).toHaveBeenCalledWith({ NextToken: undefined });

		expect(awsSecretsManager.getSecret('secret1')).toBe('secret1-value');
		expect(awsSecretsManager.getSecret('secret2')).toBe('secret2-value');
		expect(awsSecretsManager.getSecret('secret3')).toBe('secret3-value');
	});

	describe('STS Cross-Account Authentication', () => {
		const mockSend = jest.fn();

		beforeEach(() => {
			// Mock STSClient constructor and send method
			(STSClient as jest.MockedClass<typeof STSClient>).mockImplementation(
				() =>
					({
						send: mockSend,
					}) as any,
			);
		});

		it('should successfully assume role with STS', async () => {
			const roleArn = 'arn:aws:iam::123456789012:role/CrossAccountSecretsRole';
			const externalId = 'unique-external-id';
			const sessionName = 'n8n-test-session';

			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				stsRoleArn: roleArn,
				stsExternalId: externalId,
				stsSessionName: sessionName,
			};

			// Mock successful STS assume role response
			mockSend.mockResolvedValueOnce({
				Credentials: {
					AccessKeyId: 'ASSUMED-ACCESS-KEY',
					SecretAccessKey: 'ASSUMED-SECRET-KEY',
					SessionToken: 'ASSUMED-SESSION-TOKEN',
					Expiration: new Date(Date.now() + 3600000), // 1 hour from now
				},
			});

			await awsSecretsManager.init(context);

			// Verify STS was called with correct parameters
			expect(mockSend).toHaveBeenCalledWith(
				expect.objectContaining({
					input: {
						RoleArn: roleArn,
						RoleSessionName: sessionName,
						ExternalId: externalId,
					},
				}),
			);

			// Verify SecretsManager was initialized with assumed role credentials
			expect(SecretsManager).toHaveBeenCalledWith({
				region,
				credentials: {
					accessKeyId: 'ASSUMED-ACCESS-KEY',
					secretAccessKey: 'ASSUMED-SECRET-KEY',
					sessionToken: 'ASSUMED-SESSION-TOKEN',
				},
			});
		});

		it('should assume role without external ID when not provided', async () => {
			const roleArn = 'arn:aws:iam::123456789012:role/CrossAccountSecretsRole';

			context.settings = {
				region,
				authMethod: 'autoDetect',
				stsRoleArn: roleArn,
				// No external ID or session name provided
			};

			mockSend.mockResolvedValueOnce({
				Credentials: {
					AccessKeyId: 'ASSUMED-ACCESS-KEY',
					SecretAccessKey: 'ASSUMED-SECRET-KEY',
					SessionToken: 'ASSUMED-SESSION-TOKEN',
					Expiration: new Date(Date.now() + 3600000),
				},
			});

			await awsSecretsManager.init(context);

			expect(mockSend).toHaveBeenCalledWith(
				expect.objectContaining({
					input: {
						RoleArn: roleArn,
						RoleSessionName: 'n8n-external-secrets', // Default session name
						// ExternalId should not be present
					},
				}),
			);
		});

		it('should handle STS assume role failure', async () => {
			const roleArn = 'arn:aws:iam::123456789012:role/InvalidRole';

			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				stsRoleArn: roleArn,
			};

			// Mock STS failure
			mockSend.mockRejectedValueOnce(new Error('Access denied'));

			await expect(awsSecretsManager.init(context)).rejects.toThrow('Access denied');
		});

		it('should handle missing credentials in STS response', async () => {
			const roleArn = 'arn:aws:iam::123456789012:role/CrossAccountSecretsRole';

			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				stsRoleArn: roleArn,
			};

			// Mock STS response without credentials
			mockSend.mockResolvedValueOnce({
				Credentials: undefined,
			});

			await expect(awsSecretsManager.init(context)).rejects.toThrow(
				'Failed to assume role: No credentials returned',
			);
		});

		it('should fall back to regular authentication when no STS role is configured', async () => {
			context.settings = {
				region,
				authMethod: 'iamUser',
				accessKeyId,
				secretAccessKey,
				// No STS configuration
			};

			await awsSecretsManager.init(context);

			// STS should not be called
			expect(mockSend).not.toHaveBeenCalled();

			// SecretsManager should be initialized with regular credentials
			expect(SecretsManager).toHaveBeenCalledWith({
				region,
				credentials: {
					accessKeyId,
					secretAccessKey,
				},
			});
		});

		it('should work with autoDetect authentication and STS', async () => {
			const roleArn = 'arn:aws:iam::123456789012:role/CrossAccountSecretsRole';

			context.settings = {
				region,
				authMethod: 'autoDetect',
				stsRoleArn: roleArn,
			};

			mockSend.mockResolvedValueOnce({
				Credentials: {
					AccessKeyId: 'ASSUMED-ACCESS-KEY',
					SecretAccessKey: 'ASSUMED-SECRET-KEY',
					SessionToken: 'ASSUMED-SESSION-TOKEN',
					Expiration: new Date(Date.now() + 3600000),
				},
			});

			await awsSecretsManager.init(context);

			// STS client should be created without explicit credentials (autoDetect)
			expect(STSClient).toHaveBeenCalledWith({ region });

			// SecretsManager should use assumed role credentials
			expect(SecretsManager).toHaveBeenCalledWith({
				region,
				credentials: {
					accessKeyId: 'ASSUMED-ACCESS-KEY',
					secretAccessKey: 'ASSUMED-SECRET-KEY',
					sessionToken: 'ASSUMED-SESSION-TOKEN',
				},
			});
		});
	});
});
