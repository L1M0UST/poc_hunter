EXPLOIT_SIGNATURE_COLUMNS = [
    "id",
    "related_cve",
    "vulnerability_name",
    "url_signature",
    "http_method",
    "header_signature",
    "body_signature",
    "response_status",
    "response_indicator",
    "source",
    "description",
]

EXPLOIT_SIGNATURE_RESULT_KEYS = [
    "related_cve",
    "vulnerability_name",
    "url_signature",
    "http_method",
    "header_signature",
    "body_signature",
    "response_status",
    "response_indicator",
    "description",
]

EXPECTED_JSON_SHAPE = {
    "extractable": True,
    "signature": {
        "related_cve": "",
        "vulnerability_name": "",
        "url_signature": "",
        "http_method": "",
        "header_signature": "",
        "body_signature": "",
        "response_status": "",
        "response_indicator": "",
        "description": "",
    },
}
