from sigma.backends.stix import stixBackend
from sigma.pipelines.stix import stix_2_0
from sigma.collection import SigmaCollection

""" 
Linux arguments (a0, a1, a2, etc.) transform to process:command_line LIKE '% <argument> %'
"""


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


"""
Split full path of file into file:name and file:parent_directory_ref.path 
in case of file:name 
(applied also for - process:binary_ref.name and process:parent_ref.binary_ref.name) 
"""


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

def test_stix_2_split_image_windows_single_like_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|contains:
                        - c:\\tmp\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name LIKE '%foo.exe%') AND (file:parent_directory_ref.path LIKE '%c:\\\\tmp\\\\bar%')]"]


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


# Special cases - startswith, endswith, contains, etc.

# case1 - only directory path (no filename)
def test_stix_2_split_image_windows_single_case1_pipeline():
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
                        - c:\\foo\\bar\\
                condition: sel
        """)
    ) == ["[file:parent_directory_ref.path = 'c:\\\\foo\\\\bar\\\\']"]


# case2 - only directory path (no filename) - contains
def test_stix_2_split_image_windows_single_case2_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|contains:
                        - c:\\foo\\bar\\
                condition: sel
        """)
    ) == ["[file:parent_directory_ref.path LIKE '%c:\\\\foo\\\\bar\\\\%']"]


# case3 - only directory path (no filename) - startswith
def test_stix_2_split_image_windows_single_case3_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|startswith:
                        - c:\\foo\\bar\\
                condition: sel
        """)
    ) == ["[file:parent_directory_ref.path LIKE 'c:\\\\foo\\\\bar\\\\%']"]


# case4 - only directory path (no filename) - endswith
def test_stix_2_split_image_windows_single_case4_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|endswith:
                        - c:\\foo\\bar\\
                condition: sel
        """)
    ) == ["[file:parent_directory_ref.path LIKE '%c:\\\\foo\\\\bar\\\\']"]


# case5 - only filename (no directory path)
def test_stix_2_split_image_windows_single_case5_pipeline():
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
                        - \\foo.exe
                condition: sel
        """)
    ) == ["[file:name = 'foo.exe']"]


# case6 - only filename (no directory path) - contains
def test_stix_2_split_image_windows_single_case6_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|contains:
                        - \\foo.exe
                condition: sel
        """)
    ) == ["[file:name LIKE '%foo.exe%']"]


# case7 - only filename (no directory path) - startswith
def test_stix_2_split_image_windows_single_case7_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|startswith:
                        - \\foo.exe
                condition: sel
        """)
    ) == ["[file:name LIKE 'foo.exe%']"]


# case8 - only filename (no directory path) - endswith
def test_stix_2_split_image_windows_single_case8_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|endswith:
                        - \\foo.exe
                condition: sel
        """)
    ) == ["[file:name LIKE '%foo.exe']"]


# case9 - directory path and filename
def test_stix_2_split_image_windows_single_case9_pipeline():
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
                        - c:\\foo\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name = 'foo.exe') AND (file:parent_directory_ref.path = 'c:\\\\foo\\\\bar')]"]


# case10 - directory path and filename - contains
def test_stix_2_split_image_windows_single_case10_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|contains:
                        - c:\\foo\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name LIKE 'foo.exe%') AND (file:parent_directory_ref.path LIKE 'c:\\\\foo\\\\bar%')]"]


# case11 - directory path and filename - startswith
def test_stix_2_split_image_windows_single_case11_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|startswith:
                        - c:\\foo\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name LIKE 'foo.exe%') AND (file:parent_directory_ref.path = 'c:\\\\foo\\\\bar')]"]


# case12 - directory path and filename - endswith
def test_stix_2_split_image_windows_single_case12_pipeline():
    assert stixBackend(stix_2_0()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    filename|endswith:
                        - c:\\foo\\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name LIKE 'foo.exe') AND (file:parent_directory_ref.path = '%c:\\\\foo\\\\bar')]"]


# case13 - directory path and filename
def test_stix_2_split_image_windows_single_case13_pipeline():
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
                        - \\bar\\foo.exe
                condition: sel
        """)
    ) == ["[(file:name = 'foo.exe') AND (file:parent_directory_ref.path = 'bar')]"]