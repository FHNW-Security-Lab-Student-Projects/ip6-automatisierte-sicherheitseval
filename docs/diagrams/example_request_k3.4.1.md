```bash
start_validation(
    target_path="tests/fixtures/heap_overflow/simple_overflow.c",
    target_function="create_user",
    vulnerability_type="stack_overflow",
    function_args='[
        {"type": "pointer", "size": 64},
        {"type": "pointer", "size": 20, "is_struct": true}
    ]',
    structs='[
        {
            "name": "u",
            "location": "arg",
            "arg_index": 1,
            "size": 20,
            "fields": [
                {"size": 16, "is_input": true},
                {"size": 4, "is_critical": true}
            ]
        }
    ]'
)
```