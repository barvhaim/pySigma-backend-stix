from sigma.backends.stix import stixBackend
from sigma.pipelines.stix import stix_2_0
from sigma.collection import SigmaCollection


def test_stix_2_linux_arguments_like_transform():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: linux
                service: auditd
            detection:
                sel:
                    a0: 'gzip'
                    a1: '-f'
                    a2: '/tmp/foo'
                condition: sel
        """)
    ) == ["[(process:command_line LIKE '% gzip %') AND (process:command_line LIKE '% -f %') AND "
          "(process:command_line LIKE '% /tmp/foo %')]"]


def test_stix_2_split_image_windows_single_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename:
                        - c:\\tmp\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name = 'foo.exe') AND (file:parent_directory_ref.path = 'c:\\\\tmp\\\\bar')]"]


def test_stix_2_split_image_windows_single_not_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename:
                        - c:\\tmp\\bar\\foo.exe
                condition: not sel
        """)
    ) == ["[((file:name != 'foo.exe') OR (file:parent_directory_ref.path != 'c:\\\\tmp\\\\bar'))]"]


def test_stix_2_split_image_windows_multi_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename:
                        - c:\\tmp\\bar\\foo.exe
                        - baz.exe
                condition: sel
        """)
    ) == ["[((file:name = 'foo.exe') AND (file:parent_directory_ref.path = 'c:\\\\tmp\\\\bar')) OR "
          "(file:name = 'baz.exe')]"]


def test_stix_2_split_image_windows_multi_not_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename:
                        - c:\\tmp\\bar\\foo.exe
                        - baz.exe
                condition: not sel
        """)
    ) == ["[(((file:name != 'foo.exe') OR (file:parent_directory_ref.path != 'c:\\\\tmp\\\\bar')) AND "
          "(file:name != 'baz.exe'))]"]
