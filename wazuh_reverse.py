from mitmproxy import http
import json

class WazuhProxy:
    def request(self, flow: http.HTTPFlow):
        # Only target OpenSearch search calls
        # Fast reject (cheap checks first)
        if "/internal/search/opensearch" in flow.request.path:
            if flow.request.method != "POST":
                return
            if not flow.request.headers.get("Content-Type", "").startswith("application/json"):
                return
        
            try:
                data = json.loads(flow.request.text)

                # Index check (MANDATORY)
                params = data.get("params")

                if not params or params.get("index")  != "vpn-sessions*":
                    return
            
                # Navigate safely to the bool query
                bool_q = data["params"]["body"]["query"]["bool"]            
                filters = bool_q.get("filter", [])
            
                # Find original @timestamp range
                start_time = None
                end_time = None
                ts_filter_idx = None

                for i, f in enumerate(filters):
                    if "range" in f and "@timestamp" in f["range"]:
                        ts_range = f["range"]["@timestamp"]
                        start_time = ts_range.get("gte")
                        end_time = ts_range.get("lte")
                        ts_filter_idx = i
                        break

                # Only transform if timestamps were found
                # Do nothing if no time range
                if not start_time or not end_time:
                    return
            
                # 🔁 Replace ONLY the timestamp range filter
                filters[ts_filter_idx] = {
                    "range": {
                        "login_time": {
                            "lte": end_time
                        }
                    }
                }

                # Ensure should block exists
                should = bool_q.get("should")
                if should is None:
                    should = []
                    bool_q["should"] = should

                # Required should clauses
                logout_range = {
                    "range": {
                        "logout_time": {
                            "gte": start_time
                        }
                    }
                }

                logout_missing = {
                    "bool": {
                        "must_not": {
                            "exists": {
                                "field": "logout_time"
                            }
                        }
                    }
                }
                # Avoid duplicates
                if logout_range not in should:
                    should.append(logout_range)

                if logout_missing not in should:
                    should.append(logout_missing)

                # Enforce minimum_should_match
                bool_q["minimum_should_match"] = 1

                # Write modified request back
                flow.request.text = json.dumps(data)

                print("[+] Wazuh OpenSearch query rewritten (login/logout logic)")

            except Exception as e:
                print("[-] Wazuh proxy error:", e)

addons = [WazuhProxy()]
