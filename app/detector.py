from app.rule_manager import run_agent_rules, run_rules


def inspect_request(username, password, ip_address):
    """
    Pass the request to the Rule Manager.
    """

    return run_rules(
        username,
        password,
        ip_address
    )


def inspect_agent_report(url: str, title: str, search: str, ip_address: str):
    """
    Inspect a Guardian agent report for suspicious content.
    """

    report_text = " ".join(filter(None, [url, title, search]))
    return run_agent_rules(report_text, ip_address)
