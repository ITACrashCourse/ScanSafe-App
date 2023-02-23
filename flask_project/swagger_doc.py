HOME_PAGE_DOC = {
    'summary': 'Opening home page',
    'description': 'Endpoint to open home.html page.',
    'tags': ['Home page'],
    'parameters': [],
    'responses': {}
}

SCAN_TEXT_DOC = {
    'summary': 'This endpoint extracts all URLs from the text',
    'description': 'This endpoint extracts all URLs from the text.',
    'tags': ['Scanning text'],
    'parameters': [],
    'responses': {}
}

DOMAINS_URLS_QUERY_DOC = {
    'summary': 'Perform a search for domains and urls',
    'description': 'Perform a search for domains and urls.',
    'tags': ['Search'],
    'parameters': [],
    'responses': {}
}

SEND_URL_TO_IPQS_DOC = {
    'summary': 'Sending URL to IP Quality Score',
    'description': 'Function sends a user-provided URL address to IPQS for checking safety parameters',
    'tags': ['Sending URL'],
    'requestBody': {
        'description': 'JSON object containing URL address for check',
        'required': True,
        'content': {
            'application/json': {
                'schema': {},
                'example': {
                    "url": "https://regex101.com/library"
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'JSON object containing URL information from IP Quality Score service',
            'content': {
                'application/json': {
                    'schema': {},
                    'example': {
                        "domain": "regex101.com",
                        "ip": "78.47.220.195",
                        "safety_status": "Low risk",
                        "url": "https://regex101.com/library"
                    }
                }
            }
        },
        'default': {
            'description': 'Retrieval data from IPQS failed',
            'content': {
                'application/json': {
                    'schema': {},
                    'example': {
                        None: None
                    }
                }
            }
        }
    }
}


URL_SCAN_INFO_DOC = {
    'summary': 'Receiving scan info for URL/URLs from database',
    'description': 'Function has to get single URL/domain or many number of addresses',
    'tags': ['Getting scan info'],
    'requestBody': {
        'description': 'JSON object containing ULRs addresses.',
        'required': True,
        'content': {
            'application/json': {
                'schema': {},
                'example': {
                    "1": "https://regex101.com/"
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Scan info for received ULR information retrieved successfully.',
            'content': {
                'application/json': {
                    'schema': {},
                    'example':{
                        "url": "https://regex101.com/",
                        "category": "Computers & internet",
                        "server": "",
                        "unsafe": 'false',
                        "risk_score": 0,
                        "suspicious": 'false',
                        "malware": 'false',
                        "phishing": 'false',
                        "spamming": 'false',
                        "parking": 'false',
                        "dns_server": 'false',
                        "dns_valid": 'true'
                    }
                }
            }
        },
        'default': {
            'description': 'Scan info retrival failed.',
            'content': {
                'application/json': {
                    'schema': {},
                    'example':{None:None}
                }
            }

        }
    }
}


URL_DOMAINS_SCAN_INFO_DOC = {
    'summary': 'Receiving scan info for URLs/domains from database',
    'description': 'Function has to get single URL/domain or many number of addresses',
    'tags': ['Getting scan info'],
    'requestBody': {
        'description': 'JSON object containing ULRs or domains addresses.',
        'required': True,
        'content': {
            'application/json': {
                'schema': {},
                'example': {
                    "1": "regex101.com"
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Scan info for received ULRs or domain information retrieved successfully.',
            'content': {
                'application/json': {
                    'schema': {},
                    'example': {
                        "url": "regex101.com",
                        "category": "Computers & internet",
                        "server": "",
                        "unsafe": 'false',
                        "risk_score": 0,
                        "suspicious": 'false',
                        "malware": 'false',
                        "phising": 'false',
                        "spamming": 'false',
                        "parking": 'false',
                        "dns_server": 'false',
                        "dns_valid": 'true'
                    }
                }
            }
        },
        'default': {
            'description': 'Scan info retrival failed.',
            'content': {
                'application/json': {
                    'schema': {},
                    'example': {None: None}
                }
            }
        }
    }
}

