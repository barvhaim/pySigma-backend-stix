from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, \
    ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.types import SigmaCompareExpression, SigmaString
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional, Union


class stixBackend(TextQueryBackend):
    """stix backend."""
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "stix backend"
    formats: Dict[str, str] = {
        "default": "Plain stix queries",
        "stix": "'stix' output format",
    }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[
        str] = "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "
    not_eq_token: ClassVar[str] = " != "

    # String output
    ## Fields
    ### Quoting
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$")  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[
        bool] = True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape: ClassVar[str] = "\\"  # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[bool] = True  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile(
        "\\s")  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = "'"  # string quoting character (added as escaping character)
    escape_char: ClassVar[str] = "\\"  # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = "\\"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }
    like_token = "LIKE"

    # Regular expressions
    re_expression: ClassVar[
       str] = "{field} MATCHES '{regex}'"  # Regular expression query as format string with placeholders {field} and {regex}
    re_not_expression: ClassVar[str] = "{field} NOT MATCHES '{regex}'"
    re_escape_char: ClassVar[str] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped

    # Numeric comparison operators
    compare_op_expression: ClassVar[
        str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[
        str] = "{field} is null"  # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[
        bool] = True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression: ClassVar[
        str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[
        str] = "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[
        str] = "contains-all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = ""  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = ""  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = ""  # String used as query if final query only contains deferred expression

    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None,
                 collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)

    @staticmethod
    def _check_is_field_valid(field: str):
        """Validate field name."""
        if ":" not in field:
            raise NotImplementedError("Backend does not support rules with unmapped values")

    @staticmethod
    def _escape_str_value(value: str) -> str:
        """Escape value string."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        within_not = state.processing_state.get("within_not", False)
        and_token = self.and_token if not within_not else self.or_token
        try:
            if self.token_separator == and_token:  # don't repeat the same thing triple times if separator equals and token
                joiner = and_token
            else:
                joiner = self.token_separator + and_token + self.token_separator

            return joiner.join((
                converted
                for converted in (
                self.convert_condition_group(arg, state)
                for arg in cond.args
            )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            ))
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        within_not = state.processing_state.get("within_not", False)
        or_token = self.or_token if not within_not else self.and_token
        try:
            if self.token_separator == or_token:  # don't repeat the same thing triple times if separator equals or token
                joiner = or_token
            else:
                joiner = self.token_separator + or_token + self.token_separator

            return joiner.join((
                converted
                for converted in (
                self.convert_condition_group(arg, state) for arg in cond.args
            )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            ))
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        state.processing_state['within_not'] = not (state.processing_state['within_not']) \
            if 'within_not' in state.processing_state else True
        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return self.convert_condition_group(arg, state)
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):  # negate deferred expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    del state.processing_state['within_not']
                    return expr
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> \
            Union[str, DeferredQueryExpression]:
        self._check_is_field_valid(cond.field)
        within_not = state.processing_state.get("within_not", False)
        eq_token = self.not_eq_token if within_not else self.eq_token
        like_token = f'{self.not_token} {self.like_token}' if within_not else self.like_token
        try:
            field = cond.field
            val = self._escape_str_value(cond.value.to_plain())
            val_no_wc = val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi)
            # contains case
            if val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single):
                result = field + self.token_separator + like_token + self.token_separator + \
                         self.str_quote + f'%{val_no_wc}%' + self.str_quote
            # startswith case
            elif val.endswith(self.wildcard_single) and not val.startswith(self.wildcard_single):
                result = field + self.token_separator + like_token + self.token_separator + \
                         self.str_quote + f'{val_no_wc}%' + self.str_quote
            # endswith case
            elif val.startswith(self.wildcard_single) and not val.endswith(self.wildcard_single):
                result = field + self.token_separator + like_token + self.token_separator + \
                         self.str_quote + f'%{val_no_wc}' + self.str_quote
            # plain equals case
            else:
                result = field + eq_token + self.str_quote + val + self.str_quote
            return result
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals string value expressions are not supported by the backend")

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> \
            Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        self._check_is_field_valid(cond.field)
        within_not = state.processing_state.get("within_not", False)
        try:
            if within_not:
                return self.escape_and_quote_field(cond.field) + self.not_eq_token + str(cond.value)
            return self.escape_and_quote_field(cond.field) + self.eq_token + str(cond.value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_field_eq_val_bool(self, cond : ConditionFieldEqualsValueExpression,
                                            state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = bool value expressions"""
        self._check_is_field_valid(cond.field)
        cond.value = SigmaString(str(cond.value))
        return self.convert_condition_field_eq_val_str(cond, state)

    def convert_condition_field_eq_val_re(self, cond: ConditionFieldEqualsValueExpression,
                                          state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        self._check_is_field_valid(cond.field)
        within_not = state.processing_state.get("within_not", False)
        try:
            field = cond.field
            value = self._escape_str_value(cond.value.regexp)
            if within_not:
                return self.re_not_expression.format(
                    field=field,
                    regex=value
                )
            else:
                return self.re_expression.format(
                    field=field,
                    regex=value
                )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Reg expressions are not supported by the backend.")

    def convert_condition_field_eq_val_null(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState)\
            -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        raise NotImplementedError("Null expressions are not supported by the backend.")

    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        raise NotImplementedError("Value-only strings are not supported by the backend.")

    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        raise NotImplementedError("Value-only strings are not supported by the backend.")

    def convert_condition_val_re(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions."""
        raise NotImplementedError("Value-only strings are not supported by the backend.")

    def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
        return f'[{query}]'

    def finalize_output_stix(self, queries: List[str]) -> Any:
        return "\n".join(queries)
