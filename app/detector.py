from app.rule_manager import run_rules

def inspect_request(username, password, ip_address):
    """
    Pass the request to the Rule Manager.
    """

    return run_rules(
        username,
        password,
        ip_address
    )

