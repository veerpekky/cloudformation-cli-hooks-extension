# pylint: disable=protected-access,redefined-outer-name
# pylint: disable=line-too-long
import tempfile
from unittest.mock import ANY, patch, MagicMock
from argparse import ArgumentParser
import uuid
from contextlib import contextmanager
import pytest
from botocore.exceptions import ClientError

from hook_extension.build_guard_hook import (
    validate_control_names,
    upload_guard_files_to_s3,
    handle_controls_file,
    is_valid_bucket_name,
    prep_guard_hook,
    create_execution_role,
    activate_type,
    set_type_configuration,
    is_valid_hook_alias,
    _build_guard_hook,
    setup_parser
)

@contextmanager
def capture_sys_exit():
    try:
        yield
    except SystemExit as e:
        raise SystemExit(e.code) from e

TEST_BUCKET_NAME = "test-bucket"
TEST_CONTROL_NAMES = ["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]

@pytest.fixture
def s3_client():
    with patch("boto3.client") as mock_client:
        yield mock_client.return_value

#---------------------------------------------------------------------------------------------------

class TestEntryPoint:
    def test_command_available(self):
        parser = ArgumentParser()
        with patch("hook_extension.build_guard_hook._build_guard_hook") as mock_build_guard_hook:
            setup_parser(parser.add_subparsers())
            args = parser.parse_args(["build-guard-hook", "--s3bucket", "test-bucket", "--controls", "CT.SERVICE.PR.1", "CT.SERVICE.PR.2"])
            args.command(args)

        mock_build_guard_hook.assert_called_once_with(args)

    def test_command_without_required_args_fails(self):
        parser = ArgumentParser()
        with pytest.raises(SystemExit):
            setup_parser(parser.add_subparsers())
            parser.parse_args(["build-guard-hook"])

    def test_command_with_controls_file_arg(self):
        parser = ArgumentParser()
        with patch("hook_extension.build_guard_hook._build_guard_hook") as mock_build_guard_hook:
            setup_parser(parser.add_subparsers())
            args = parser.parse_args(["build-guard-hook", "--s3bucket", "test-bucket", "--controls-file", "controls.txt"])
            args.command(args)

        mock_build_guard_hook.assert_called_once_with(args)

#---------------------------------------------------------------------------------------------------

class TestCommandLineArguments:
    @pytest.mark.parametrize("s3bucket, controls, controls_file", [
        ("test-bucket", ["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"], None),
        ("another-bucket", None, "controls.txt"),
    ])
    def test_parser(
        self,
        s3bucket,
        controls,
        controls_file
        ):
        parser = ArgumentParser()
        setup_parser(parser.add_subparsers())

        args = ["build-guard-hook", "--s3bucket", s3bucket]
        if controls:
            args.extend(["--controls"] + controls)
        if controls_file:
            args.append("--controls-file")
            args.append(controls_file)

        parsed = parser.parse_args(args)
        assert parsed.s3bucket == s3bucket
        assert parsed.controls == controls
        assert parsed.controls_file == controls_file

#---------------------------------------------------------------------------------------------------

class TestValidateControlNames:
    @pytest.mark.parametrize("control_names,exists_side_effect,expected_valid,expected_invalid", [
        (TEST_CONTROL_NAMES, lambda x: True, TEST_CONTROL_NAMES, []),
        (TEST_CONTROL_NAMES, lambda x: x.endswith("CT.SERVICE.PR.1.guard"), ["CT.SERVICE.PR.1"], ["CT.SERVICE.PR.2"]),
        (["CT.SERVICE.PR.1", "CT.SERVICE.PR.3"], lambda x: x.endswith("CT.SERVICE.PR.1.guard"), ["CT.SERVICE.PR.1"], ["CT.SERVICE.PR.3"]),
        (["CT.SERVICE.PR.4", "CT.SERVICE.PR.5"], lambda x: False, [], ["CT.SERVICE.PR.4", "CT.SERVICE.PR.5"])
    ])
    @patch("os.path.exists")
    def test_validate_control_names(
        self,
        mock_exists,
        control_names,
        exists_side_effect,
        expected_valid,
        expected_invalid
        ):
        mock_exists.side_effect = exists_side_effect
        valid, invalid, _ = validate_control_names(control_names)
        assert valid == expected_valid
        assert invalid == expected_invalid

#---------------------------------------------------------------------------------------------------

class TestUploadGuardFilesToS3:
    @pytest.mark.parametrize("file_data", [
        ("data", "data"),
        ["fileData","moreFileData","someMoreFileData"]
        ])
    @patch("hook_extension.build_guard_hook.ZipFile")
    def test_upload_guard_files_to_s3(
        self,
        s3_client,
        file_data
        ):
        temp_files = []
        for data in file_data:
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(data.encode())
            temp_file.flush()
            temp_files.append(temp_file.name)

        with patch("os.path.join", side_effect=temp_files):
            upload_guard_files_to_s3(TEST_BUCKET_NAME, TEST_CONTROL_NAMES, s3_client)

        s3_client.upload_fileobj.assert_called_once_with(ANY, TEST_BUCKET_NAME, "guard_files.zip")

#---------------------------------------------------------------------------------------------------

class TestHandleControlsFile:
    @pytest.mark.parametrize("file_suffix,file_content,controls,controls_file,expected_result", [
        ('.json', '["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]', None, True, set(TEST_CONTROL_NAMES)),
        ('.txt', "CT.SERVICE.PR.1\nCT.SERVICE.PR.2", None, True, set(TEST_CONTROL_NAMES)),
        (None, None, TEST_CONTROL_NAMES, None, set(TEST_CONTROL_NAMES)),
        ('.json', '["CT.SERVICE.PR.1", "CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]', None, True, set(TEST_CONTROL_NAMES)),
        (None, None, TEST_CONTROL_NAMES + ["CT.SERVICE.PR.1"], None, set(TEST_CONTROL_NAMES)),
        ('.csv', "CT.SERVICE.PR.1,CT.SERVICE.PR.2", None, True, None)
    ])
    def test_handle_controls_file(
        self,
        file_suffix,
        file_content,
        controls,
        controls_file,
        expected_result
        ):
        if controls_file:
            with tempfile.NamedTemporaryFile('w', suffix=file_suffix, delete=False) as temp_file:
                temp_file.write(file_content)
                temp_file.flush()
                temp_file_name = temp_file.name
            control_names = handle_controls_file(controls, temp_file_name)
        else:
            control_names = handle_controls_file(controls, None)

        assert control_names == expected_result

#---------------------------------------------------------------------------------------------------

class TestIsValidBucketName:
    @pytest.mark.parametrize("bucket_name, expected_result", [
        ("valid-bucket-name", True),
        ("invalid_bucket", False),
        ("valid-bucket-name-with-numbers-123", True),
        ("invalid.bucket.name", False),
        ("validbucketname", True),
        ("xn--test-bucket", False),
        ("bucket-s3alias", False),
    ])
    def test_is_valid_bucket_name(
        self,
        bucket_name,
        expected_result
        ):
        result = is_valid_bucket_name(bucket_name)
        assert result == expected_result

#---------------------------------------------------------------------------------------------------

class TestPrepGuardHook:
    @pytest.mark.parametrize("controls_file_return, validate_return, s3bucket,controls_file, controls, expected_create_bucket_call", [
        (set(TEST_CONTROL_NAMES), (TEST_CONTROL_NAMES, [], True), TEST_BUCKET_NAME, None, TEST_CONTROL_NAMES, True),
        (set(TEST_CONTROL_NAMES + ["Invalid-Control"]), (TEST_CONTROL_NAMES, ["Invalid-Control"], False), TEST_BUCKET_NAME, None, TEST_CONTROL_NAMES + ["Invalid-Control"], False),
        (set(TEST_CONTROL_NAMES), (TEST_CONTROL_NAMES, [], True), TEST_BUCKET_NAME, "controls_file.txt", None, True)
    ])
    @patch("hook_extension.build_guard_hook.handle_controls_file")
    @patch("hook_extension.build_guard_hook.validate_control_names")
    @patch("hook_extension.build_guard_hook.upload_guard_files_to_s3")
    @patch("boto3.client")
    def test_prep_guard_hook(
        self,
        mock_boto3_client,
        mock_upload_guard_files_to_s3,
        mock_validate_control_names,
        mock_handle_controls_file,
        controls_file_return,
        validate_return,
        s3bucket,
        controls_file,
        controls,
        expected_create_bucket_call,
        capsys
        ):
        mock_handle_controls_file.return_value = controls_file_return
        mock_validate_control_names.return_value = validate_return

        with tempfile.NamedTemporaryFile(delete=False) as temp_file_1, \
             tempfile.NamedTemporaryFile(delete=False) as temp_file_2:
            temp_file_1.write(b"data")
            temp_file_2.write(b"data")
            temp_file_1.flush()
            temp_file_2.flush()

            file_paths = [temp_file_1.name, temp_file_2.name]

            with patch("os.path.join", side_effect=file_paths):
                mock_s3_client = mock_boto3_client.return_value
                mock_s3_client = mock_boto3_client('s3', region_name='eu-central-1')

                mock_s3_client.head_bucket.side_effect = ClientError({'Error': {'Code': '404'}}, 'head_bucket') if expected_create_bucket_call else None

                if expected_create_bucket_call:
                    mock_s3_client.create_bucket.return_value = {}
                    mock_s3_client.put_bucket_encryption.return_value = {}

                if validate_return[2]:
                    prep_guard_hook(controls_file_return, s3bucket, mock_s3_client)

                    if expected_create_bucket_call:
                        mock_s3_client.create_bucket.assert_called_with(Bucket=s3bucket, CreateBucketConfiguration={'LocationConstraint': 'eu-central-1'})
                        mock_s3_client.put_bucket_encryption.assert_called_with(
                            Bucket=s3bucket,
                            ServerSideEncryptionConfiguration={
                                'Rules': [
                                    {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
                                ]
                            }
                        )
                        mock_upload_guard_files_to_s3.assert_called_with(
                            s3bucket, TEST_CONTROL_NAMES, mock_s3_client
                        )
                else:
                    with pytest.raises(SystemExit) as exc_info, capture_sys_exit() as capture:
                        prep_guard_hook(controls_file_return, s3bucket, mock_s3_client)

                    captured = capsys.readouterr()
                    assert "Error: The following proactive control names are invalid or not recognized." in captured.out
                    assert exc_info.value.code == 1
                    mock_s3_client.create_bucket.assert_not_called()
                    mock_s3_client.put_bucket_encryption.assert_not_called()
                    mock_upload_guard_files_to_s3.assert_not_called()

    @patch("hook_extension.build_guard_hook.handle_controls_file")
    @patch("hook_extension.build_guard_hook.validate_control_names")
    @patch("hook_extension.build_guard_hook.upload_guard_files_to_s3")
    @patch("boto3.client")
    def test_prep_guard_hook_create_bucket_failure(
        self,
        mock_boto3_client,
        mock_upload_guard_files_to_s3,
        mock_validate_control_names,
        mock_handle_controls_file,
        capsys):
        mock_handle_controls_file.return_value = set(TEST_CONTROL_NAMES)
        mock_validate_control_names.return_value = (TEST_CONTROL_NAMES, [], True)

        with tempfile.NamedTemporaryFile(delete=False) as temp_file_1, \
            tempfile.NamedTemporaryFile(delete=False) as temp_file_2:
            temp_file_1.write(b"data")
            temp_file_2.write(b"data")
            temp_file_1.flush()
            temp_file_2.flush()

            file_paths = [temp_file_1.name, temp_file_2.name]

            with patch("os.path.join", side_effect=file_paths):
                mock_s3_client = mock_boto3_client.return_value
                mock_s3_client = mock_boto3_client('s3', region_name='eu-central-1')
                mock_s3_client.head_bucket.side_effect = ClientError({'Error': {'Code': '404'}}, 'head_bucket')
                mock_s3_client.create_bucket.side_effect = ClientError(
                    error_response={'Error': {
                        'Code': 'SomeErrorCode', 'Message': 'Failed to create bucket'
                        }},
                    operation_name='CreateBucket'
                )

                with pytest.raises(SystemExit) as exc_info:
                    prep_guard_hook(set(TEST_CONTROL_NAMES), TEST_BUCKET_NAME, mock_s3_client)

                assert exc_info.value.code == 1

    @patch("hook_extension.build_guard_hook.handle_controls_file")
    @patch("hook_extension.build_guard_hook.validate_control_names")
    @patch("hook_extension.build_guard_hook.upload_guard_files_to_s3")
    @patch("boto3.client")
    def test_prep_guard_hook_bucket_forbidden(
        self, mock_boto3_client,
        mock_upload_guard_files_to_s3,
        mock_validate_control_names,
        mock_handle_controls_file,
        capsys
        ):
        mock_handle_controls_file.return_value = set(TEST_CONTROL_NAMES)
        mock_validate_control_names.return_value = (TEST_CONTROL_NAMES, [], True)

        with tempfile.NamedTemporaryFile(delete=False) as temp_file_1, \
            tempfile.NamedTemporaryFile(delete=False) as temp_file_2:
            temp_file_1.write(b"data")
            temp_file_2.write(b"data")
            temp_file_1.flush()
            temp_file_2.flush()

            file_paths = [temp_file_1.name, temp_file_2.name]

            with patch("os.path.join", side_effect=file_paths):
                mock_s3_client = mock_boto3_client.return_value
                mock_s3_client = mock_boto3_client('s3', region_name='eu-central-1')
                mock_s3_client.head_bucket.side_effect = ClientError({'Error': {'Code': '403'}}, 'head_bucket')

                with pytest.raises(SystemExit) as exc_info:
                    prep_guard_hook(set(TEST_CONTROL_NAMES), TEST_BUCKET_NAME, mock_s3_client)

                assert "Error: The S3 bucket name 'test-bucket' is already taken or you do not have permissions to access it. Please choose a different bucket name." in str(exc_info.value)
    @pytest.mark.parametrize("invalid_bucket_name", [
    "invalid_bucket",
    "invalid-bucket-name",
    "invalid.bucket.name",
    "invalidbucketname"
    ])
    @patch("hook_extension.build_guard_hook.handle_controls_file")
    @patch("hook_extension.build_guard_hook.validate_control_names")
    @patch("boto3.client")
    def test_prep_guard_hook_invalid_bucket_name(
        self,
        mock_boto3_client,
        mock_validate_control_names,
        mock_handle_controls_file,
        invalid_bucket_name,
        capsys
        ):
        mock_handle_controls_file.return_value = set(TEST_CONTROL_NAMES)
        mock_validate_control_names.return_value = (TEST_CONTROL_NAMES, [], True)

        with tempfile.NamedTemporaryFile(delete=False) as temp_file_1, \
            tempfile.NamedTemporaryFile(delete=False) as temp_file_2:
            temp_file_1.write(b"data")
            temp_file_2.write(b"data")
            temp_file_1.flush()
            temp_file_2.flush()

            file_paths = [temp_file_1.name, temp_file_2.name]

            with patch("os.path.join", side_effect=file_paths):
                mock_s3_client = mock_boto3_client.return_value
                mock_s3_client = mock_boto3_client('s3', region_name='eu-central-1')
                mock_s3_client.head_bucket.side_effect = ClientError(
                    error_response={'Error': {
                        'Code': 'InvalidBucketName',
                        'Message': f"Invalid bucket name '{invalid_bucket_name}': Bucket name must match the regex '(?!(^xn--|.+-s3alias$))^[a-z0-9][a-z0-9-]{{1,61}}[a-z0-9]$'"
                    }},
                    operation_name='HeadBucket'
                )

                with pytest.raises(SystemExit) as exc_info:
                    prep_guard_hook(set(TEST_CONTROL_NAMES), invalid_bucket_name, mock_s3_client)

                expected_error_message = f"Invalid bucket name '{invalid_bucket_name}': Bucket name must match the regex '(?!(^xn--|.+-s3alias$))^[a-z0-9][a-z0-9-]{{1,61}}[a-z0-9]$'"
                assert expected_error_message in str(exc_info.value)

#---------------------------------------------------------------------------------------------------

class TestCreateExecutionRole:
    @pytest.mark.parametrize("hook_alias_name, expected_role_name, expected_role_arn", [
        ("My::Custom::Hook", "My-Custom-Hook-ExecutionRole-12345678", "arn:aws:iam::123456789012:role/My-Custom-Hook-ExecutionRole-12345678"),
        ("Another::Hook::Name", "Another-Hook-Name-ExecutionRole-12345678", "arn:aws:iam::123456789012:role/Another-Hook-Name-ExecutionRole-12345678"),
        ("ValidHookAlias::WithNumbers::123", "ValidHookAlias-WithNumbers-123-ExecutionRole-12345678", "arn:aws:iam::123456789012:role/ValidHookAlias-WithNumbers-123-ExecutionRole-12345678"),
    ])
    @patch("hook_extension.build_guard_hook.uuid.uuid4")
    @patch("boto3.client")
    def test_create_execution_role(
        self,
        mock_boto3_client,
        mock_uuid4,
        hook_alias_name,
        expected_role_name,
        expected_role_arn,
        capsys
        ):
        mock_iam_client = mock_boto3_client.return_value
        mock_iam_client.get_user.return_value = {"User": {"Arn": "arn:aws:iam::123456789012:user/test-user"}}
        mock_uuid4.return_value = uuid.UUID("12345678901234567890123456789012")
        mock_iam_client.create_role.return_value = {"Role": {"Arn": expected_role_arn}}

        role_arn = create_execution_role(hook_alias_name)

        assert role_arn == expected_role_arn

        mock_iam_client.create_role.assert_called_once()
        mock_iam_client.put_role_policy.assert_called_once()

        captured = capsys.readouterr()
        assert f"   - Execution Role Name: '{expected_role_name}'." in captured.out
        assert f"   - Execution Role ARN: '{expected_role_arn}'." in captured.out

    @patch("boto3.client")
    def test_create_execution_role_error(self, mock_boto3_client):
        mock_iam_client = mock_boto3_client.return_value
        mock_iam_client.get_user.return_value = {"User": {"Arn": "arn:aws:iam::123456789012:user/test-user"}}
        mock_iam_client.create_role.side_effect = ClientError(
            error_response={"Error": {"Code": "SomeErrorCode", "Message": "Failed to create role"}},
            operation_name="CreateRole",
        )

        with pytest.raises(SystemExit) as exc_info:
            create_execution_role("My::Custom::Hook")

        assert exc_info.value.code == 1

#---------------------------------------------------------------------------------------------------

class TestActivateType:
    @patch("subprocess.run")
    def test_activate_type(
        self,
        mock_subprocess_run):
        exec_role_arn = "arn:aws:iam::123456789012:role/MyExecutionRole"
        hook_name = "My::Custom::Hook"

        activate_type(exec_role_arn, hook_name)

        mock_subprocess_run.assert_called_once_with(
            [
                "aws", "cloudformation", "activate-type", "--type-name", "AWS::Guard::Hook", "--type", "HOOK",
                "--publisher-id", "aws-hooks", "--type-name-alias", hook_name, "--execution-role-arn", exec_role_arn,
                "--region", "eu-central-1", "--no-cli-pager"
            ],
            check=True
        )

#---------------------------------------------------------------------------------------------------

class TestSetTypeConfiguration:
    @patch("subprocess.run")
    def test_set_type_configuration(
        self,
        mock_subprocess_run):
        failure_mode = "FAIL"
        bucket_name = "my-bucket"
        hook_name = "My::Custom::Hook"

        set_type_configuration(failure_mode, bucket_name, hook_name)

        mock_subprocess_run.assert_called_once_with(
            [
                "aws", "cloudformation", "set-type-configuration", "--type", "HOOK", "--type-name", hook_name, "--configuration",
                '{"CloudFormationConfiguration": {"HookConfiguration": {"FailureMode": "FAIL", "TargetStacks": "ALL", "Properties": {"ruleLocation": "s3://my-bucket/guard_files.zip", "logBucket": "my-bucket"}}}}',
                "--region", "eu-central-1", "--no-cli-pager"
            ],
            check=True
        )

#---------------------------------------------------------------------------------------------------

class TestIsValidHookAlias:
    @pytest.mark.parametrize("hook_alias, expected_result", [
        ("My::Custom::Hook", True),
        ("InvalidAlias", False),
        ("Valid::Alias::123", True),
        ("Short", False),
        ("Valid::Alias::With::Many::Parts", False),
    ])
    def test_is_valid_hook_alias(
        self,
        hook_alias,
        expected_result
        ):
        result = is_valid_hook_alias(hook_alias)
        assert result == expected_result

#---------------------------------------------------------------------------------------------------

class TestBuildGuardHook:
    @patch("hook_extension.build_guard_hook.prep_guard_hook")
    @patch("hook_extension.build_guard_hook.create_execution_role")
    @patch("hook_extension.build_guard_hook.activate_type")
    @patch("hook_extension.build_guard_hook.set_type_configuration")
    @patch("hook_extension.build_guard_hook.is_valid_hook_alias")
    @patch("hook_extension.build_guard_hook.is_valid_bucket_name")
    @patch("builtins.input", side_effect=["My::Custom::Hook", "fail"])
    def test_build_guard_hook(
        self,
        mock_input,
        mock_is_valid_bucket_name,
        mock_is_valid_hook_alias,
        mock_set_type_configuration,
        mock_activate_type,
        mock_create_execution_role,
        mock_prep_guard_hook,
        capsys,
    ):
        mock_is_valid_bucket_name.return_value = True
        mock_is_valid_hook_alias.return_value = True
        mock_create_execution_role.return_value = "arn:aws:iam::123456789012:role/MyExecutionRole"

        args = MagicMock()
        args.s3bucket = "test-bucket"
        args.controls = ["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]
        args.controls_file = None

        _build_guard_hook(args)

        mock_prep_guard_hook.assert_called_once_with(set(args.controls), args.s3bucket, ANY)
        mock_create_execution_role.assert_called_once_with("My::Custom::Hook")
        mock_activate_type.assert_called_once_with(mock_create_execution_role.return_value, "My::Custom::Hook")
        mock_set_type_configuration.assert_called_once_with("fail", args.s3bucket, "My::Custom::Hook")

        captured = capsys.readouterr()
        assert "Guard Hook 'My::Custom::Hook' created successfully." in captured.out

    @patch("hook_extension.build_guard_hook.prep_guard_hook")
    @patch("hook_extension.build_guard_hook.is_valid_hook_alias")
    @patch("builtins.input", side_effect=["InvalidHookAlias", SystemExit()])
    def test_build_guard_hook_invalid_hook_alias(
        self, mock_input, mock_is_valid_hook_alias, mock_prep_guard_hook, capsys
    ):
        mock_is_valid_hook_alias.return_value = False

        args = MagicMock()
        args.s3bucket = "test-bucket"
        args.controls = ["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]
        args.controls_file = None

        with pytest.raises(SystemExit):
            _build_guard_hook(args)
            mock_prep_guard_hook.assert_not_called()

        captured = capsys.readouterr()
        assert "Invalid hook alias name." in captured.out

#---------------------------------------------------------------------------------------------------

def test_setup_parser():
    parser = ArgumentParser()
    setup_parser(parser.add_subparsers())

    args_in = ["build-guard-hook", "--s3bucket", "test-bucket",
        "--controls", "CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]
    parsed = parser.parse_args(args_in)
    assert parsed.s3bucket == "test-bucket"
    assert parsed.controls == ["CT.SERVICE.PR.1", "CT.SERVICE.PR.2"]
    assert parsed.controls_file is None
