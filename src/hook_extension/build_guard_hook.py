"""
This sub command configures a first party cloudformation guard hook with selected proactive controls.
"""
import os
import json
import logging
import subprocess
import re
import uuid
import io
from json import JSONDecodeError
from zipfile import ZipFile, ZIP_DEFLATED
import boto3
from botocore.exceptions import ClientError, WaiterError

LOG = logging.getLogger(__name__)

COMMAND_NAME = "build-guard-hook"

PROACTIVE_CONTROLS_DIR = os.path.join(os.path.dirname(__file__), 'proactive_controls')

#---------------------------------------------------------------------------------------------------

def validate_control_names(control_names):
    """
    Validates the provided proactive controls and returns tuple of invalid and valid controls.

    Parameters:
        control_names (list): A list of user selected proactive control names.

    Returns:
        tuple: A tuple of two lists:
            - valid_control_names (list): List of valid proactive control names.
            - invalid_control_names (list): List of invalid proactive control names.
    """
    LOG.debug("Validating proactive control names: %s", control_names)
    valid_control_names = []
    invalid_control_names = []
    valid_control_bool = True

    for control_name in control_names:
        guard_file_path = os.path.join(PROACTIVE_CONTROLS_DIR, f"{control_name}.guard")
        if os.path.exists(guard_file_path):
            valid_control_names.append(control_name)
        else:
            invalid_control_names.append(control_name)

    if invalid_control_names:
        valid_control_bool = False

    return valid_control_names, invalid_control_names, valid_control_bool

#---------------------------------------------------------------------------------------------------

def upload_guard_files_to_s3(bucket_name, control_names, s3_client):
    """
    Uploads guard files as a zip file to provisioned S3 bucket.

    Parameters:
        bucket_name (str): Name of the S3 bucket.
        control_names (list): List of proactive control names.
        s3_client (boto3.client): Boto3 S3 client object.
    
    Returns:
        None
    """
    LOG.debug("Uploading guard files to S3 bucket: %s", bucket_name)
    zip_file_buffer = io.BytesIO()
    with ZipFile(zip_file_buffer, 'w', ZIP_DEFLATED) as zip_file:
        for control_name in control_names:
            guard_file_path = os.path.join(PROACTIVE_CONTROLS_DIR, f"{control_name}.guard")
            try:
                LOG.debug("Adding file to zip: %s", guard_file_path)
                zip_file.write(guard_file_path, os.path.basename(guard_file_path))
            except (OSError, ValueError, OverflowError) as e:
                LOG.error("Error adding file to zip: %s", e)
                raise SystemExit(1) from e

    zip_file_key = "guard_files.zip"
    try:
        LOG.debug("Uploading the guard files as a zip file: %s", zip_file_key)
        zip_file_buffer.seek(0)
        s3_client.upload_fileobj(zip_file_buffer, bucket_name, zip_file_key)
        for control_name in control_names:
            print(f"   - {control_name}")
    except ClientError as e:
        LOG.error("Error uploading zip file: %s", e)
        raise SystemExit(f"Error uploading zip file: {e}") from e
    finally:
        zip_file_buffer.close()

#---------------------------------------------------------------------------------------------------

def handle_controls_file(controls, controls_file):
    """
    Parses provided control names, in text or file formats and returns a list of the control names.

    Parameters:
        controls (list): List of user selected proactive control names.
        controls_file (str): Path to a file containing a list of proactive control names.

    Returns:
        list: List of control names.
    """
    control_names = None
    error_message = None

    if controls_file:
        if controls_file.endswith('.json'):
            try:
                with open(controls_file, 'r', encoding='utf-8') as file:
                    control_names = set(json.load(file))
                    LOG.debug("JSON file control names loaded: %s", control_names)
            except FileNotFoundError:
                error_message = f"Error: File '{controls_file}' not found."
            except JSONDecodeError as e:
                error_message = f"Error: '{controls_file}' is not a valid JSON file.\nJSON parsing error: {e}\n\
                    Please ensure that the file contains an array of controls (e.g. [\"CT.SERVICE.PR.1\",\"CT.SERVICE.PR.2\",\"CT.SERVICE.PR.3\"] )"
        elif controls_file.endswith('.txt'):
            try:
                with open(controls_file, 'r', encoding='utf-8') as file:
                    lines = file.readlines()
                    if any(not line.strip() for line in lines):
                        error_message = f"Error: '{controls_file}' contains empty lines.\nEach line in the file should contain a single control name."
                    else:
                        control_names = set(line.strip() for line in lines)
                        LOG.debug("Text file control names loaded: %s", control_names)
            except FileNotFoundError:
                error_message = f"Error: File '{controls_file}' not found."
            except IOError as e:
                error_message = f"Error: Failed to read '{controls_file}': {e}"

        else:
            error_message = f"Error: Unsupported file format for '{controls_file}'"

    else:
        control_names = set(controls)

    if error_message:
        LOG.debug(error_message)
        print(error_message)
        return None

    return control_names

#---------------------------------------------------------------------------------------------------

def is_valid_bucket_name(bucket_name):
    """
    Checks if the bucket name is valid according to S3 naming rules.

    Parameters:
        bucket_name (str): The bucket name to validate.

    Returns:
        bool: True if the bucket name is valid, False otherwise.
    """
    bucket_name_regex = r'(?!(^xn--|.+-s3alias$))^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'
    return bool(re.match(bucket_name_regex, bucket_name))

#---------------------------------------------------------------------------------------------------

def prep_guard_hook(control_names, bucket_name, s3_client):
    """
    Manages creation of S3 bucket, outputs validation of control names, and upload to S3 bucket for preperation of Guard Hook.

    Parameters:
        control_names (list): List of proactive control names.
        bucket_name (str): Name of the S3 bucket.
        s3_client (boto3.client): Boto3 S3 client object.

    Returns:
        None
    """
    print()
    print("Validating proactive control names...")
    valid_control_names, invalid_control_names, valid_control_bool = validate_control_names(control_names)

    if not valid_control_bool:
        LOG.debug("The following proactive control names are invalid or not recognized: %s", invalid_control_names)
        print()
        print("Error: The following proactive control names are invalid or not recognized.")
        for invalid_name in invalid_control_names:
            print(f"   - {invalid_name}")
        print()
        print("Ensure that the controls are of the form 'CT.[A-Z]+.PR.\\d+'.")
        print("Please check that the provided control names are valid with the AWS Control Tower documentation.")
        print()
        raise SystemExit(1)

    LOG.debug("Provided proactive controls valid.")
    print("   - Provided proactive controls valid.")
    print()

    if not is_valid_bucket_name(bucket_name):
        error_message = f"Invalid bucket name '{bucket_name}': Bucket name must match the regex '(?!(^xn--|.+-s3alias$))^[a-z0-9][a-z0-9-]{{1,61}}[a-z0-9]$'"
        LOG.debug(error_message)
        raise SystemExit(error_message)

    try:
        s3_client.head_bucket(Bucket=bucket_name)
        bucket_exists = True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            bucket_exists = False
        elif error_code == '403':
            error_message = f"Error: The S3 bucket name '{bucket_name}' is already taken or you do not have permissions to access it. Please choose a different bucket name."
            LOG.debug("Error checking if S3 bucket '%s' exists: %s", bucket_name, e)
            raise SystemExit(error_message) from e
        elif error_code == 'InvalidBucketName':
            error_message = e.response['Error']['Message']
            LOG.debug("Error checking if S3 bucket '%s' exists: %s", bucket_name, e)
            raise SystemExit(error_message) from e
        else:
            LOG.debug("Error checking if S3 bucket '%s' exists: %s", bucket_name, e)
            raise SystemExit(f"Error checking if S3 bucket '{bucket_name}' exists: {e}") from e

    if bucket_exists:
        LOG.debug("S3 bucket '%s' already exists. Updating the bucket...", bucket_name)
        print(f"Updating S3 bucket '{bucket_name}'...")
    else:
        LOG.debug("S3 bucket '%s' does not exist. Creating new bucket...", bucket_name)
        print(f"Creating S3 bucket '{bucket_name}'...")

        try:
            s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={
                'LocationConstraint': 'eu-central-1'
            })

            waiter = s3_client.get_waiter('bucket_exists')
            try:
                waiter.wait(Bucket=bucket_name, WaiterConfig={'MaxAttempts': 40})
            except WaiterError as e:
                LOG.debug("Error waiting for bucket to be created: %s", e)
                print(f"Error waiting for bucket '{bucket_name}' to be created: {e}")
                raise SystemExit(1) from e

            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
        except ClientError as e:
            LOG.debug("Error creating S3 bucket '%s': %s", bucket_name, e)
            print(f"Error creating S3 bucket '{bucket_name}': {e}")
            raise SystemExit(1) from e

    print("The following guard files were uploaded as a zip file: guard_files.zip.")
    upload_guard_files_to_s3(bucket_name, valid_control_names, s3_client)
    print()
    print(f"Zip file uploaded to S3 bucket '{bucket_name}'.")

#---------------------------------------------------------------------------------------------------

def create_execution_role(hook_alias_name):
    """
    Creates the execution role needed for activating the guard hook.

    Parameters:
        hook_alias_name (str): The name of the guard hook.

    Returns:
        str: The ARN of the created execution role.
    """
    region_name = 'eu-central-1'
    iam_client = boto3.client('iam', region_name=region_name)
    account_id = iam_client.get_user()['User']['Arn'].split(':')[4]

    hook_alias_name = hook_alias_name.replace('::', '-')
    role_name = f'{hook_alias_name}-ExecutionRole-{uuid.uuid4().hex[:8]}'

    script_dir = os.path.dirname(os.path.abspath(__file__))
    assume_role_policy_path = os.path.join(script_dir, 'cfn_temps', 'assume-role-policy.json')
    role_policy_path = os.path.join(script_dir, 'cfn_temps', 'role-policy.json')

    with open(assume_role_policy_path, 'r', encoding='utf-8') as file:
        assume_role_policy_document = json.load(file)

    assume_role_policy_document['Statement'][0]['Condition']['StringEquals']['aws:SourceAccount'] = account_id
    assume_role_policy_document['Statement'][0]['Condition']['StringLike']['aws:SourceArn'][0] = \
        assume_role_policy_document['Statement'][0]['Condition']['StringLike']['aws:SourceArn'][0].replace('__REGION__', region_name).replace('__ACCOUNT_ID__', account_id).replace('__HOOK_ALIAS__', hook_alias_name)

    with open(role_policy_path, 'r', encoding='utf-8') as file:
        role_policy_document = json.load(file)

    try:
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
            MaxSessionDuration=8400,
            Path="/",
            Tags=[
                {'Key': 'Name', 'Value': role_name},
                {'Key': 'AppName', 'Value': 'hook-deployment'},
            ]
        )

        waiter = iam_client.get_waiter('role_exists')
        try:
            waiter.wait(RoleName=role_name)
        except WaiterError as e:
            LOG.debug("Error waiting for role to be created: %s", e)
            print(f"Error waiting for role '{role_name}' to be created: {e}")
            raise SystemExit(1) from e

        role_arn = role_response['Role']['Arn']

        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='HookTypePolicy',
            PolicyDocument=json.dumps(role_policy_document)
        )

        LOG.debug("Execution role created: %s", role_arn)
        print(f"   - Execution Role Name: '{role_name}'.")
        print(f"   - Execution Role ARN: '{role_arn}'.")

    except ClientError as e:
        LOG.debug("Error creating execution role: %s", e)
        print(f"Error creating execution role: {e}")
        raise SystemExit(1) from e

    return role_arn

#---------------------------------------------------------------------------------------------------

def activate_type(exec_role_arn, hook_name):
    """
    Calls activate_type for the guard hook.

    Parameters:
        exec_role_arn (str): The ARN of the execution role.
        hook_name (str): The name of the guard hook.

    Returns:
        None
    """
    subprocess.run(
        [
            'aws', 'cloudformation', 'activate-type', '--type-name', 'AWS::Guard::Hook', '--type', 'HOOK', '--publisher-id', 'aws-hooks', '--type-name-alias', hook_name, '--execution-role-arn', exec_role_arn, '--region', 'eu-central-1', '--no-cli-pager'
        ], check=True
    )

#---------------------------------------------------------------------------------------------------

def set_type_configuration(failure_mode, bucket_name, hook_name):
    """
    Calls set_type_configuration for the guard hook.

    Parameters:
        failure_mode (str): Failure mode for the guard hook. (FAIL|WARN)
        bucket_name (str): Name of the S3 bucket.
        hook_name (str): Name of the guard hook.

    Returns:
        None
    """
    rule_location = f"s3://{bucket_name}/guard_files.zip"
    subprocess.run(
        [
            'aws', 'cloudformation', 'set-type-configuration', '--type', 'HOOK', '--type-name', hook_name, '--configuration',
            json.dumps({
                'CloudFormationConfiguration': {
                    'HookConfiguration': {
                        'FailureMode': failure_mode.upper(),
                        'TargetStacks': 'ALL',
                        'Properties': {
                            'ruleLocation': rule_location,
                            'logBucket': bucket_name
                        }
                    }
                }
            }), '--region', 'eu-central-1', '--no-cli-pager'
        ], check=True
    )

#---------------------------------------------------------------------------------------------------

def is_valid_hook_alias(hook_alias):
    """
    Checks if the hook alias name is valid based on length and the pattern.

    Parameters:
        hook_alias (str): The hook alias name to validate.

    Returns:
        bool: True if the hook alias name is valid, False otherwise.
    """
    pattern = r'^[a-zA-Z0-9_]+::[a-zA-Z0-9_]+::[a-zA-Z0-9_]+$'
    if len(hook_alias) < 10:
        return False
    return bool(re.match(pattern, hook_alias))

#---------------------------------------------------------------------------------------------------

def _build_guard_hook(args):
    """
    Activates and configures the first party cloudformation guard hook with specified proactive controls and hook alias.

    Parameters:
        args (Namespace): Arguments passed in for the CLI command.
            Required keys in Namespace: 's3bucket', 'controls'/'controls_file'. All default to None.

    Returns:
        None
    """
    LOG.info("Building guard hook with arguments: %s", args)
    s3_client = boto3.client('s3', region_name='eu-central-1')
    bucket_name = args.s3bucket
    controls = args.controls
    controls_file = args.controls_file

    control_names = handle_controls_file(controls, controls_file)
    if control_names is None:
        return

    prep_guard_hook(control_names, bucket_name, s3_client)

    while True:
        hook_alias_name = input("\nEnter a hook alias name (e.g. My::Custom::Hook): ")
        if is_valid_hook_alias(hook_alias_name):
            break
        else:
            print("Invalid hook alias name. The name should follow the pattern '[a-zA-Z0-9_]+::[a-zA-Z0-9_]+::[a-zA-Z0-9_]+' and be at least 10 characters long.")

    while True:
        failure_mode = input("Enter the desired failure mode ('warn' or 'fail'): ").lower()
        if failure_mode in ['warn', 'fail']:
            break
        else:
            print("Invalid failure mode. Please enter 'warn' or 'fail'.")

    LOG.debug("Creating execution role...")
    print("\nCreating execution role...")
    execution_role_arn = create_execution_role(hook_alias_name)

    LOG.debug("Activating hook...")
    print("\nActivating hook...")
    activate_type(execution_role_arn, hook_alias_name)

    LOG.debug("Configuring hook...")
    print("\nConfiguring hook...")
    set_type_configuration(failure_mode, bucket_name, hook_alias_name)

    LOG.debug("Guard Hook configured successfully.")
    print(f"\nGuard Hook '{hook_alias_name}' created successfully.")

#---------------------------------------------------------------------------------------------------

def setup_parser(parser):
    build_guard_hook_parser = parser.add_parser(COMMAND_NAME, description=__doc__)
    build_guard_hook_parser.set_defaults(command=_build_guard_hook)

    required_args_parser = build_guard_hook_parser.add_argument_group('required arguments')
    required_args_parser.add_argument("-s3","--s3bucket", required=True, help="Name of S3 bucket to hold proactive controls.")

    control_group = required_args_parser.add_mutually_exclusive_group(required=True)
    control_group.add_argument("-c","--controls", nargs="+", help="List selected proactive control names for hook configuration.\
                               Either this argument or -f/--controls-file is required.")
    control_group.add_argument("-f", "--controls-file", help="Path to text/JSON file with proactive control names for hook configuration.\
                               Either this argument or -c/--controls is required.")
