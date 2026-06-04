import json
import pytest
import os
import tempfile
from unittest.mock import patch

from adpa import parse_policy

def test_parse_policy_none_or_empty():
    assert parse_policy(None) == {}
    assert parse_policy('') == {}

def test_parse_policy_valid_json():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
        json.dump({"test": "data"}, tmp)
        tmp_path = tmp.name

    try:
        result = parse_policy(tmp_path)
        assert result == {"test": "data"}
    finally:
        os.remove(tmp_path)

def test_parse_policy_invalid_json():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
        tmp.write("{invalid_json_here")
        tmp_path = tmp.name

    try:
        with patch('adpa.logging.error') as mock_log:
            result = parse_policy(tmp_path)
            assert result == {}
            mock_log.assert_called_once()
            args, _ = mock_log.call_args
            assert args[0].startswith("Failed to read policy file:")
    finally:
        os.remove(tmp_path)

def test_parse_policy_nonexistent_file():
    with patch('adpa.logging.error') as mock_log:
        result = parse_policy("this_file_does_not_exist_at_all.json")
        assert result == {}
        mock_log.assert_called_once()
        args, _ = mock_log.call_args
        assert args[0].startswith("Failed to read policy file:")
