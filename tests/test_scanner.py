import pytest
import asyncio
import socket
from core.scanner import VanguardEngine
from utils.validators import VanguardValidator

@pytest.mark.asyncio
async def test_validator_ip():
    assert VanguardValidator.validate_target("127.0.0.1") is True
    assert VanguardValidator.validate_target("8.8.8.8") is True
    assert VanguardValidator.validate_target("invalid-ip") is False

@pytest.mark.asyncio
async def test_validator_domain():
    assert VanguardValidator.validate_target("google.com") is True
    assert VanguardValidator.validate_target("sub.example.co.uk") is True

@pytest.mark.asyncio
async def test_port_sanitizer():
    assert VanguardValidator.sanitize_port("80") == [80]
    assert VanguardValidator.sanitize_port("1-5") == [1, 2, 3, 4, 5]
    assert VanguardValidator.sanitize_port("22,80,443") == [22, 80, 443]

@pytest.mark.asyncio
async def test_engine_resolution():
    engine = VanguardEngine([80])
    ip, family = await engine._resolve_target("127.0.0.1")
    assert ip == "127.0.0.1"
    assert family == socket.AF_INET

@pytest.mark.asyncio
async def test_service_detection():
    engine = VanguardEngine([80])
    service, version, severity, os_hint = engine._detect_service(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert service == "SSH"
    assert version == "2.0"
    assert os_hint == "OpenSSH_8.2p1"
