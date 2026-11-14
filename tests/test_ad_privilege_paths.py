import contextlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from src.ad_privilege_paths import GraphError, assess, html_report, load_json, main, validate_graph


def fixture():
    sid = "S-1-5-21-10-20-30-"
    return {
        "schema_version": "1.0", "start_sid": sid + "1100",
        "target_sid": sid + "512", "complete": True,
        "nodes": [
            {"id": sid + "1100", "kind": "User", "label": "alice"},
            {"id": sid + "2001", "kind": "Group", "label": "Helpdesk"},
            {"id": sid + "2002", "kind": "Group", "label": "Delegated"},
            {"id": sid + "512", "kind": "Group", "label": "Domain Admins"},
        ],
        "edges": [
            {"from": sid + "1100", "to": sid + "2001", "relation": "member_of", "evidence": "user memberOf"},
            {"from": sid + "2001", "to": sid + "2002", "relation": "member_of", "evidence": "nested membership"},
            {"from": sid + "2002", "to": sid + "512", "relation": "can_modify_group", "evidence": "Allow WriteDacl ACE"},
        ],
        "indicators": [
            {"principal_sid": sid + "2001", "kind": "dcsync_rights_candidate",
             "object": "domain_root", "evidence": "both replication rights"},
            {"principal_sid": sid + "2002", "kind": "gpo_acl_control_candidate",
             "object": "synthetic gpo", "evidence": "WriteDacl but link unknown"},
        ],
        "warnings": [], "coverage": {"groups_enumerated": 4},
    }


class PathAssessmentTests(unittest.TestCase):
    def test_nested_membership_and_acl_candidate_path(self):
        r = assess(fixture())
        self.assertEqual(r["status"], "potential_acl_path")
        self.assertEqual([s["relation"] for s in r["steps"]],
                         ["member_of", "member_of", "can_modify_group"])
        self.assertFalse(r["confirmed_exploit"])
        self.assertEqual(r["steps"][-1]["to"], "Domain Admins")

    def test_member_of_only_is_not_called_attack(self):
        graph = fixture()
        graph["edges"][-1]["relation"] = "member_of"
        result = assess(graph)
        self.assertEqual(result["status"], "membership_path_found")
        self.assertFalse(result["contains_acl_candidate"])

    def test_no_path_is_not_proof_of_no_risk(self):
        graph = fixture()
        graph["edges"].pop()
        r = assess(graph)
        self.assertEqual(r["status"], "no_path_in_collected_scope")
        self.assertEqual(r["steps"], [])
        self.assertIn("No observed path is not proof", r["interpretation"])

    def test_dcsync_and_gpo_not_automatic_domain_admin_paths(self):
        graph = fixture()
        graph["edges"].pop()
        r = assess(graph)
        self.assertEqual(r["status"], "no_path_in_collected_scope")
        self.assertEqual({x["kind"] for x in r["high_impact_exposures"]},
                         {"dcsync_rights_candidate", "gpo_acl_control_candidate"})
        self.assertTrue(all(not x["is_domain_admin_membership"] for x in r["high_impact_exposures"]))

    def test_disconnected_privileged_principal_not_assigned_to_start(self):
        graph = fixture()
        graph["edges"].pop()
        graph["indicators"].append({
            "principal_sid": graph["target_sid"],
            "kind": "dcsync_rights_candidate", "evidence": "DA rights",
        })
        r = assess(graph)
        self.assertFalse(any(x["principal"] == "Domain Admins" for x in r["high_impact_exposures"]))

    def test_rejects_unknown_node_or_identity(self):
        g = fixture()
        g["edges"][0]["to"] = "nonexistent"
        with self.assertRaises(GraphError):
            validate_graph(g)
        g = fixture()
        del g["complete"]
        with self.assertRaises(GraphError):
            validate_graph(g)

    def test_no_network_or_mutation_and_input_limits(self):
        p = Path(__file__).resolve().parents[1] / "src" / "ad_privilege_paths.py"
        s = p.read_text()
        self.assertNotIn("subprocess.", s)
        self.assertNotIn("requests.", s)
        self.assertNotIn("ldap3", s)

    def test_html_escapes_untrusted_display_names(self):
        g = fixture()
        g["nodes"][0]["label"] = '<img src=x onerror=alert(1)>'
        report = html_report(assess(g))
        self.assertNotIn("<img", report)
        self.assertIn("&lt;img", report)

    def test_cli_report_output_and_fail_closed_incomplete_status(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "graph.json"
            output = Path(directory) / "report.json"
            graph = fixture()
            graph["complete"] = False
            graph["warnings"] = ["Group ACL inventory was incomplete"]
            source.write_text(json.dumps(graph), encoding="utf-8")
            with contextlib.redirect_stdout(StringIO()), contextlib.redirect_stderr(StringIO()):
                code = main([str(source), "--output", str(output)])
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(output.read_text())["graph_complete"], False)
            with contextlib.redirect_stdout(StringIO()), contextlib.redirect_stderr(StringIO()):
                again = main([str(source), "--output", str(output)])
            self.assertEqual(again, 2)

    def test_python_cli_default_json(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "graph.json"
            src.write_text(json.dumps(fixture()))
            out = StringIO()
            with contextlib.redirect_stdout(out):
                status = main([str(src)])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(out.getvalue())["status"], "potential_acl_path")


if __name__ == "__main__":
    unittest.main()
