DEFAULT_DELAY=1
DURATION_KEY='duration'
def get_delay_duration(opts=None):
    if not isinstance(opts, dict) or not DURATION_KEY in opts:
        return DEFAULT_DELAY
    else:
        duration=opts[DURATION_KEY]
        return duration

DEFAULT_CODE='2.05 Content'
COAP_CODE_KEY='code'
def get_new_coap_code(opts=None):
    if not isinstance(opts, dict) or not COAP_CODE_KEY in opts:
        return DEFAULT_CODE
    else:
        new_coap_code=opts[COAP_CODE_KEY]
        return new_coap_code
