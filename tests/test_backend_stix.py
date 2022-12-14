import pytest
from sigma.collection import SigmaCollection
from sigma.backends.stix import stixBackend


@pytest.fixture
def stix_backend():
    return stixBackend()


def test_stix_minimal_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:A: valueA
                condition: sel
        """)
    ) == ["[field:A = 'valueA']"]


def test_stix_minimal_int_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:A: 1234
                condition: sel
        """)
    ) == ["[field:A = 1234]"]


def test_stix_minimal_str_int_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:A: '1234'
                condition: sel
        """)
    ) == ["[field:A = '1234']"]


def test_stix_minimal_escaping_1_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:A: '/etc/passwd'
                condition: sel
        """)
    ) == ["[field:A = '/etc/passwd']"]


def test_stix_minimal_escaping_2_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name: "'x:0:'"
                condition: sel
        """)
    ) == ["[file:name = '\\'x:0:\\'']"]


def test_stix_minimal_escaping_3_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name: 'C:\Windows\system32\DllHost.exe'
                condition: sel
        """)
    ) == ["[file:name = 'C:\\\\Windows\\\\system32\\\\DllHost.exe']"]


def test_stix_minimal_bool_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:A: True
                condition: sel
        """)
    ) == ["[field:A = 'True']"]


def test_stix_minimal_not_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: valueA
                condition: not sel
        """)
    ) == ["[field:a != 'valueA']"]


def test_stix_minimal_not_int_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: 1337
                    field:b: 42
                    field:c: 'w00t'
                condition: not sel
        """)
    ) == ["[((field:a != 1337) OR (field:b != 42) OR (field:c != 'w00t'))]"]


def test_stix_minimal_not_not_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: valueA
                condition: not (not sel)
        """)
    ) == ["[(field:a = 'valueA')]"]


def test_stix_minimal_not_two_sel_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: valueA
                condition: (not sel) and sel
        """)
    ) == ["[(field:a != 'valueA') AND (field:a = 'valueA')]"]


def test_stix_contains_list_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a|contains:
                        - valueA
                        - valueB
                condition: sel
        """)
    ) == ["[(field:a LIKE '%valueA%') OR (field:a LIKE '%valueB%')]"]


def test_stix_not_contains_list_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a|contains:
                        - valueA
                        - valueB
                condition: not sel
        """)
    ) == ["[((field:a NOT LIKE '%valueA%') AND (field:a NOT LIKE '%valueB%'))]"]


def test_stix_minimal_not_two_sel_1_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    field:a|contains: valueA
                sel2:
                    field:b|contains|all: 
                        - valueB
                        - valueC
                condition: not sel1 and sel2
        """)
    ) == ["[(field:a NOT LIKE '%valueA%') AND ((field:b LIKE '%valueB%') AND (field:b LIKE '%valueC%'))]"]


def test_stix_minimal_not_two_sel_2_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    field:a|contains: 
                        - valueA1
                        - valueA2
                sel2:
                    field:b|contains|all: 
                        - valueB
                        - valueC
                condition: not sel1 and sel2
        """)
    ) == ["[(((field:a NOT LIKE '%valueA1%') AND (field:a NOT LIKE '%valueA2%'))) "
          "AND ((field:b LIKE '%valueB%') AND (field:b LIKE '%valueC%'))]"]


def test_stix_and_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: valueA
                    field:b: valueB
                condition: sel
        """)
    ) == ["[(field:a = 'valueA') AND (field:b = 'valueB')]"]


def test_stix_or_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    field:a: valueA
                sel2:
                    field:b: valueB
                condition: 1 of sel*
        """)
    ) == ["[(field:a = 'valueA') OR (field:b = 'valueB')]"]


def test_stix_and_or_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a:
                        - valueA1
                        - valueA2
                    field:b:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["[((field:a = 'valueA1') OR (field:a = 'valueA2')) AND ((field:b = 'valueB1') OR (field:b = 'valueB2'))]"]


def test_stix_or_and_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    field:a: valueA1
                    field:b: valueB1
                sel2:
                    field:a: valueA2
                    field:b: valueB2
                condition: 1 of sel*
        """)
    ) == ["[((field:a = 'valueA1') AND (field:b = 'valueB1')) OR ((field:a = 'valueA2') AND (field:b = 'valueB2'))]"]


def test_stix_in_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ["[(field:a = 'valueA') OR (field:a = 'valueB') OR (field:a LIKE 'valueC%')]"]


def test_stix_regex_query(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name|re: '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['
                condition: sel
        """)
    ) == ["[file:name MATCHES '\\\\$PSHome\\\\[\\\\s*\\\\d{1,3}\\\\s*\\\\]\\\\s*\\\\+\\\\s*\\\\$PSHome\\\\[']"]


def test_stix_not_regex_query(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name|re: 'foo'
                condition: not sel
        """)
    ) == ["[file:name NOT MATCHES 'foo']"]


def test_stix_like_query(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name: 
                        - '*.exe'
                        - 'foo*'
                        - '*foo.bar*'
                condition: sel
        """)
    ) == ["[(file:name LIKE '%.exe') OR (file:name LIKE 'foo%') OR (file:name LIKE '%foo.bar%')]"]


def test_stix_not_like_query(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    file:name: 
                        - '*.exe'
                        - 'foo*'
                        - '*foo.bar*'
                condition: not sel
        """)
    ) == ["[((file:name NOT LIKE '%.exe') AND (file:name NOT LIKE 'foo%') AND (file:name NOT LIKE '%foo.bar%'))]"]


def test_stix_cidr_query(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    ipv4-addr:value|cidr: 192.168.0.0/24
                condition: sel
        """)
    ) == ["[(ipv4-addr:value LIKE '192.168.0.%')]"]


def test_stix_and_not_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: valueA
                    field:b: valueB
                condition: not sel
        """)
    ) == ["[((field:a != 'valueA') OR (field:b != 'valueB'))]"]


def test_stix_or_not_expression(stix_backend: stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field:a: 
                        - valueA1
                        - valueA2
                condition: not sel
        """)
    ) == ["[((field:a != 'valueA1') AND (field:a != 'valueA2'))]"]


def test_stix_null_expression(stix_backend: stixBackend):
    with pytest.raises(NotImplementedError):
        stix_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field:A: null
                    condition: sel
            """)
        )


def test_stix_minimal_int_unmapped_expression_exception(stix_backend: stixBackend):
    with pytest.raises(NotImplementedError):
        stix_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        EventID: 1234
                    condition: sel
            """)
        )


def test_stix_minimal_str_unmapped_expression_exception(stix_backend: stixBackend):
    with pytest.raises(NotImplementedError):
        stix_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        EventID: valueA
                    condition: sel
            """)
        )


def test_stix_minimal_str_whitespace_unmapped_expression_exception(stix_backend: stixBackend):
    with pytest.raises(NotImplementedError):
        stix_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field name: valueA
                    condition: sel
            """)
        )


def test_stix_keywords_expression_exception(stix_backend: stixBackend):
    with pytest.raises(NotImplementedError):
        stix_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords: 
                        - valueA1
                    condition: keywords
            """)
        )
