import pytest
from sigma.collection import SigmaCollection
from sigma.backends.stix import stixBackend

@pytest.fixture
def stix_backend():
    return stixBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_stix_and_expression(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["[fieldA = 'valueA' AND fieldB = 'valueB']"]

def test_stix_or_expression(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["[fieldA = 'valueA' OR fieldB = 'valueB']"]

def test_stix_and_or_expression(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["[(fieldA = 'valueA1' OR fieldA = 'valueA2') AND (fieldB = 'valueB1' OR fieldB = 'valueB2')]"]

def test_stix_or_and_expression(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ["[fieldA = 'valueA1' AND fieldB = 'valueB1' OR fieldA = 'valueA2' AND fieldB = 'valueB2']"]

def test_stix_in_expression(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ["[fieldA = 'valueA' OR fieldA = 'valueB' OR fieldA LIKE 'valueC%']"]

def test_stix_regex_query(stix_backend : stixBackend):
    assert stix_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: '.+\\@example\\.com$'
                    fieldB: foo
                condition: sel
        """)
    ) == ["[fieldA MATCHES '.+\\@example\\.com$' AND fieldB = 'foo']"]

# def test_stix_cidr_query(stix_backend : stixBackend):
#     assert stix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field|cidr: 192.168.0.0/16
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# def test_stix_field_name_with_whitespace(stix_backend : stixBackend):
#     assert stix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.

# def test_stix_not_expression(stix_backend : stixBackend):
#     assert stix_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     fieldA: valueA
#                     fieldB: valueB
#                 condition: not sel
#         """)
#     ) == ["[ fieldA != 'valueA' OR fieldB != 'valueB' ]"]


# def test_stix_stix_output(stix_backend : stixBackend):
#     """Test for output format stix."""
#     # TODO: implement a test for the output format
#     pass


