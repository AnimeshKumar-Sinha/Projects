from solution import solution

assert solution({"a": 1, "b": 2}) == {1: "a", 2: "b"}
assert solution({}) == {}
assert solution({"x": 10}) == {10: "x"}
assert solution({1: "a", 2: "b"}) == {"a": 1, "b": 2}
