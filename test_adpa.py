import json
import pytest
import os
import tempfile
from unittest.mock import patch

from adpa import parse_policy, parse_high_value

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

def test_parse_high_value_none_or_empty():
    assert parse_high_value(None) == ['Domain Admins', 'Enterprise Admins']
    assert parse_high_value('') == ['Domain Admins', 'Enterprise Admins']

def test_parse_high_value_valid_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        # Include normal lines, lines with trailing/leading spaces, and empty lines
        tmp.write("Domain Admins\n")
        tmp.write("  Enterprise Admins  \n")
        tmp.write("\n")
        tmp.write("Custom Admin Group\n")
        tmp_path = tmp.name

    try:
        result = parse_high_value(tmp_path)
        assert result == ['Domain Admins', 'Enterprise Admins', 'Custom Admin Group']
    finally:
        os.remove(tmp_path)

def test_parse_high_value_nonexistent_file():
    with patch('adpa.logging.error') as mock_log:
        result = parse_high_value("this_file_does_not_exist_at_all.txt")
        assert result == ['Domain Admins', 'Enterprise Admins']
        mock_log.assert_called_once()
        args, _ = mock_log.call_args
        assert args[0].startswith("Failed to read high value file:")
