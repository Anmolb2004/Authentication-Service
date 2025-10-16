import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

export class MainStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const table = new dynamodb.Table(this, 'UsersTable', {
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const jwtSecret = new secretsmanager.Secret(this, 'JwtSecret', {
        generateSecretString: { secretStringTemplate: '{}', generateStringKey: 'key', excludeCharacters: '"/\\@' }
    });

    const apiLambda = new lambda.Function(this, 'ApiFunction', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'main.handler',
      code: lambda.Code.fromAsset('../src/api', {
        bundling: {
          image: lambda.Runtime.PYTHON_3_9.bundlingImage,
          command: ['bash', '-c', 'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output'],
          platform: 'linux/amd64',
        },
      }),
      environment: {
        TABLE_NAME: table.tableName,
        JWT_SECRET_KEY: jwtSecret.secretValueFromJson('key').unsafeUnwrap(),
        // ===== FIX START: Hardcode the stage name to break the cycle =====
        API_GATEWAY_STAGE: 'prod',
        // ===== FIX END =====
      },
      timeout: cdk.Duration.seconds(30),
    });

    table.grantReadWriteData(apiLambda);
    jwtSecret.grantRead(apiLambda);

    const api = new apigateway.LambdaRestApi(this, 'ApiGateway', {
      handler: apiLambda,
      proxy: true,
    });

    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url });
  }
}