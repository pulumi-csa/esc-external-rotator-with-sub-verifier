import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as pulumiservice from "@pulumi/pulumiservice";

const config = new pulumi.Config();

// The org/env to accept — baked into the Lambda at deploy time.
// The handler rejects any JWT whose sub doesn't match these values.
// allowedEnv is also required here because it doubles as the ESC environment name.
const allowedOrg = config.require("allowedOrg");
const allowedEnv = config.require("allowedEnv");

// IAM role for the Lambda
const role = new aws.iam.Role("rotatorRole", {
  assumeRolePolicy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Action: "sts:AssumeRole",
        Effect: "Allow",
        Principal: { Service: "lambda.amazonaws.com" },
      },
    ],
  }),
});

new aws.iam.RolePolicyAttachment("rotatorBasicExecution", {
  role: role.name,
  policyArn: "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
});

// API Gateway — created first so we can derive the adapter URL for the Lambda env var
const api = new aws.apigatewayv2.Api("rotatorApi", {
  protocolType: "HTTP",
  description: "ESC external rotator adapter",
});

new aws.apigatewayv2.Stage("rotatorStage", {
  apiId: api.id,
  name: "$default",
  autoDeploy: true,
});

// The Lambda's ADAPTER_URL must equal the ESC `url` config value exactly —
// Pulumi Cloud sets that same URL as the JWT `aud` claim.
const adapterUrl = pulumi.interpolate`${api.apiEndpoint}/rotate`;

const fn = new aws.lambda.Function("rotatorFn", {
  runtime: "nodejs20.x",
  handler: "rotator-handler.handler",
  role: role.arn,
  code: new pulumi.asset.AssetArchive({
    "rotator-handler.js": new pulumi.asset.FileAsset("./rotator-handler.js"),
  }),
  timeout: 30,
  environment: {
    variables: {
      // The full URL Pulumi Cloud will POST to; used to validate the JWT `aud` claim
      ADAPTER_URL: adapterUrl,
      // Sub claim verification — set at deploy time, checked at request time
      ALLOWED_ORG: allowedOrg,
      ...(allowedEnv ? { ALLOWED_ENV: allowedEnv } : {}),
    },
  },
});

const integration = new aws.apigatewayv2.Integration("rotatorIntegration", {
  apiId: api.id,
  integrationType: "AWS_PROXY",
  integrationUri: fn.arn,
  payloadFormatVersion: "2.0",
});

new aws.apigatewayv2.Route("rotatorRoute", {
  apiId: api.id,
  routeKey: "POST /rotate",
  target: integration.id.apply((id: string) => `integrations/${id}`),
});

new aws.lambda.Permission("apiGatewayInvoke", {
  action: "lambda:InvokeFunction",
  function: fn.name,
  principal: "apigateway.amazonaws.com",
  sourceArn: api.executionArn.apply((arn: string) => `${arn}/*`),
});

// ESC environment wired up to the rotator adapter
const escProject = config.get("escProject") ?? "default";

const environment = new pulumiservice.Environment("rotatorEnv", {
  organization: pulumi.getOrganization(),
  project: escProject,
  name: allowedEnv,
  yaml: adapterUrl.apply(
    (url: string) =>
      new pulumi.asset.StringAsset(`values:
  myCredentials:
    fn::rotate::external:
      inputs:
        url: ${url}
        request:
          service: my-service
`)
  ),
});

export const rotatorUrl = adapterUrl;
export const environmentName = environment.name;
