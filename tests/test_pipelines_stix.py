import pytest
from sigma.backends.stix import stixBackend
from sigma.pipelines.stix import stix_2_0
from sigma.collection import SigmaCollection


def test_stix_2_fields_mapping():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename: foo.exe
                    user: 1234
                    destinationport: 1337
                condition: sel
        """)
    ) == ["[(file:name = 'foo.exe') AND (user-account:user_id = '1234') AND (network-traffic:dst_port = 1337)]"]
