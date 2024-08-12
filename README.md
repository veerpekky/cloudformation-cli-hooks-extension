# AWS CloudFormation CLI Hooks Extension

The CloudFormation CLI (cfn) allows you to author your own CFN extension providers that can be used by CloudFormation.

This extension library provides more commands for managing and configuring your Resource Hooks.


### Documentation

Primary documentation for the CloudFormation CLI can be found at the [AWS Documentation](https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html) site.

### Installation

If you are using this package to build hook providers for CloudFormation, install the [CloudFormation CLI Hooks Extension](https://github.com/aws-cloudformation/cloudformation-cli-hooks-extension) - this will automatically install the the [CloudFormation CLI](https://github.com/aws-cloudformation/cloudformation-cli)! A Python virtual environment is recommended.

```shell
pip3 install cloudformation-cli-hooks-extension
```

### Usage

All of these commands (exluding `build-guard-hook`) are meant to be run from inside your pre-initialized Hooks project directory. You can initialize a new project by using the `cfn init` command from the [CloudFormation CLI](https://github.com/aws-cloudformation/cloudformation-cli?tab=readme-ov-file#command-init). All of the commands use the `cfn hook` prefix, ex. `cfn hook describe`.

#### Command: describe

To get more details about hook versions registered in your account, use the `describe` command. This will return the following properties:

- Description
- Created at
- Last updated at
- Default version
- Failure mode
- Target stacks
- Stack filters (if any)
- Configured properties
- Target types
- Testing status

The details for the default version will be returned by default. Optionally, the `--version-id` can be passed to describe a specific version.

```bash
cfn hook describe
```

Sample output:

```
No version specified, using default version

Selected AWS::CloudFormation::SampleHook version 00000001

Description: Example hook
Version 00000001 Created at: 2023-09-28 04:44:14.402000+00:00
Version 00000001 Last updated at: 2023-09-28 04:44:14.402000+00:00

Current configuration (only applies to default version):
  Default version: 00000001
  Configured behavior:
    Failure mode: WARN
    Target stacks: ALL
    Stack Filters:
      Filtering Criteria: ANY
      StackNames:
        Include: ['stack-name-0', 'stack-name-1', 'stack-name-2']
        Exclude: ['stack-name-3', 'stack-name-4', 'stack-name-5']
      StackRoles:
        Exclude: ['arn:aws:iam::000000000000:role/stack-role-0', 'arn:aws:iam::000000000000:role/stack-role-1', 'arn:aws:iam::000000000000:role/stack-role-2']

  No configured properties.

This Hook is configured to target:
  preCreate:
    AWS::S3::Bucket

Testing status: NOT_TESTED
 Warning: This Type version hasn't been tested yet. Run TestType to test it.
```

### Command: set-default-version

To set a specific version of your hooks as the default version, use the `set-default-version` command.

```bash
cfn hook set-default-version --version-id 1
```

This command return nothings, but you can then use `cfn hook describe` to check the default version set in your account.

### Command: configure

To set the type configuration of your hook, use the `configure` command.

You will first need to save your type configuration as a json file and then specify the file path in the command.


```bash
cfn hook configure --configuration-path ./myHookTypeConfig.json
```

Sample output:

```
ConfigurationArn: arn:aws:cloudformation:us-east-1:000000000000:type-configuration/hook/AWS-CloudFormation-SampleHook/default
```

## Experimental Commands

To enable experimental commands: you will need to set the environment variable `CFN_CLI_HOOKS_EXPERIMENTAL` to `enabled`. Example for the Bash shell: `export CFN_CLI_HOOKS_EXPERIMENTAL=enabled`.

### Command: enable-lambda-function-invoker

To activate and set the type configuration of the `AWSSamples::LambdaFunctionInvoker::Hook`third-party [hook](https://github.com/aws-cloudformation/aws-cloudformation-samples/tree/main/hooks/python-hooks/lambda-function-invoker) in your AWS account, use the `enable-lambda-function-invoker` command.

This hook will use the IAM role that you pass to `--execution-role-arn` to invoke the Lambda function that you pass to the `--lambda-function-arn` argument. Make sure the Lambda function is in the same region as the hook that you're activating; the Lambda function can also be in another account (but still, it needs to be in the same region as the hook). Ensure that the execution role IAM policy and the Lambda resource policy have been configured accordingly.

Optionally, `--failure-mode`, `--alias`, and `--include-targets` can all be specified with the following behavior:

- `--failure-mode` changes the failure mode to either `FAIL` or `WARN` (Default is `FAIL`).
- `--alias` changes the type name for this hook in your account. For example, this can be used to change `AWSSamples::LambdaFunctionInvoker::Hook` to `MyCompany::MyOrganization::S3BucketCheckHook`.
- `--include-targets` filters the targets (resource types) for which this hook will be invoked. This can be passed as a comma-separated string (for example, `--include-targets "AWS::S3::*,AWS::DynamoDB::Table"`) (Default is ALL resource types).

Note: Unlike the others, you do not need to run this command from inside an existing Hooks project directory.

See the following example of how to run the `enable-lambda-function-invoker` command; note that the `--region` argument needs to be passed here if the default region configured in your AWS CLI is **not** set to `us-east-2` (the same region in which the Lambda function exists).

```bash
cfn hook enable-lambda-function-invoker \
--lambda-function-arn arn:aws:lambda:us-east-2:123456789012:function:my-function:1 \
--execution-role-arn arn:aws:iam::123456789012:role/ExampleRole
```

Sample output:
```
Success: AWSSamples::LambdaFunctionInvoker::Hook will now be invoked for CloudFormation deployments for ALL resources in FAIL mode.
```

### Command: build-guard-hook

This sub-command configures a first-party CloudFormation Guard Hook with selected proactive controls. It performs the following steps:

1. Validates the provided proactive control names.
2. Creates or updates an S3 bucket (specified by the `--s3bucket` argument) and uploads the selected guard files as a zip file.
3. Creates an execution role for the Guard Hook.
4. Activates the Guard Hook with a specified alias name.
5. Configures the Guard Hook with the specified failure mode (`warn` or `fail`) and the S3 bucket location for the guard files.

#### Usage

```bash
cfn hook configure --configuration-path ./myHookTypeConfig.json
```
or
```bash
cfn hook build-guard-hook --s3bucket <bucket-name> --controls-file <file-path>
```

#### Arguments

- `--s3bucket`/`-s3` (required): Name of the S3 bucket to hold the proactive controls.
- `--controls`/`-c`: List of selected proactive control names for hook configuration. Either this argument or `--controls-file` is required.
- `--controls-file`/`-f`: Path to a text or JSON file containing the proactive control names for hook configuration. Either this argument or `--controls` is required.

#### Interactive Prompts

The command will prompt you for the following inputs:

1. **Hook Alias Name**: Enter a hook alias name following the pattern `[a-zA-Z0-9_]+::[a-zA-Z0-9_]+::[a-zA-Z0-9_]+` and at least 10 characters long (e.g., `My::Custom::Hook`).
2. **Failure Mode**: Enter the desired failure mode (`warn` or `fail`).

#### Output

The command will display the following output:

- Execution Role Name and ARN
- Progress messages for each step
- Activated and Configured Hook ARNs
- Final success message with the configured Guard Hook alias name

Sample Output:
```
$ cfn hook build-guard-hook -s3 pc-sample-bucket -f controls.txt

Validating proactive control names...
   - Provided proactive controls valid.
   
Creating S3 bucket 'pc-sample-bucket'...
   - S3 bucket 'pc-sample-bucket' created with server-side encryption enabled.

Uploading the following guard files as a zip file: guard_files.zip
   - CT.ATHENA.PR.1
   - CT.ATHENA.PR.2

Zip file uploaded to S3 bucket 'pc-sample-bucket'.

Enter a hook alias name (e.g. My::Custom::Hook): Sample::Name::Hook
Enter the desired failure mode ('warn' or 'fail'): warn

Creating execution role...
   - Execution Role Name: 'Sample-Name-Hook-ExecutionRole-XXXXXXXX'.
   - Execution Role ARN: 'arn:aws:iam::XXXXXXXXXXXX:role/Sample-Name-Hook-ExecutionRole-XXXXXXXX'.

Activating hook...
{
    "Arn": "arn:aws:cloudformation:eu-central-1:XXXXXXXXXXXX:type/hook/Sample-Name-Hook"
}

Configuring hook...
{
    "ConfigurationArn": "arn:aws:cloudformation:eu-central-1:XXXXXXXXXXXX:type-configuration/hook/Sample-Name-Hook/default"
}

Guard Hook 'Sample::Name::Hook' created successfully.
```

## Development

For developing, it's strongly suggested to install the development dependencies inside a virtual environment. (This isn't required if you just want to use this tool.)

```bash
python3 -m venv env
source env/bin/activate
pip3 install -e /path/to/cloudformation-cli-hooks-extension
```

Install `pytest-cov`, used when running unit tests for this plugin:

```shell
pip3 install pytest-cov
```

You may also want to check out the [CloudFormation CLI](https://github.com/aws-cloudformation/cloudformation-cli) if you wish to make edits to that. In this case, installing them in one operation works well:

```shell
pip3 install \
  -e /path/to/cloudformation-cli \
  -e /path/to/cloudformation-cli-hooks-extension
```

That ensures neither is accidentally installed from PyPI.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
