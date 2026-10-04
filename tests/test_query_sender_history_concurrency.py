import os
import sys
sys.path.insert(0, os.path.abspath("."))
import unittest
import threading
import concurrent.futures
from apps.agents.core.tool_registry import ToolRegistry, ToolProposal
from apps.agents.core.mcp_servers.telemetry_server import handle_record_interaction

class TestQuerySenderHistoryConcurrency(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry.get_instance()

    def test_single_call_from_worker_thread_succeeds(self):
        """Proves query_sender_history succeeds when dispatched from a worker thread."""
        result_holder = []
        error_holder = []

        def worker():
            try:
                proposal = ToolProposal(
                    tool_name="query_sender_history",
                    parameters={
                        "sender_email": "attacker@suspicious-domain.com",
                        "recipient_email": "victim@enterprise.com",
                        "sender_domain": "suspicious-domain.com",
                        "tenant_id": "tenant-worker-test"
                    },
                    reasoning="Thread test"
                )
                res = self.registry.execute_proposal(
                    tenant_id="tenant-worker-test",
                    proposal=proposal,
                    autonomy_level=1
                )
                result_holder.append(res)
            except Exception as e:
                error_holder.append(e)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=5.0)

        self.assertEqual(len(error_holder), 0, f"Worker thread raised exception: {error_holder}")
        self.assertEqual(len(result_holder), 1)
        res = result_holder[0]
        self.assertTrue(res.success, f"Tool execution failed: {res.error}")
        self.assertIsNone(res.error)
        self.assertEqual(res.output.get("is_first_time_sender"), True)
        self.assertEqual(res.output.get("historical_email_count"), 0)

    def test_concurrent_calls_no_thread_affinity_exception(self):
        """Proves multiple concurrent worker threads execute query_sender_history safely."""
        num_threads = 8
        results = []

        def call_tool(idx):
            proposal = ToolProposal(
                tool_name="query_sender_history",
                parameters={
                    "sender_email": f"sender{idx}@domain{idx}.com",
                    "recipient_email": "user@corp.com",
                    "sender_domain": f"domain{idx}.com",
                    "tenant_id": f"tenant-{idx}"
                },
                reasoning="Concurrency test"
            )
            return self.registry.execute_proposal(
                tenant_id=f"tenant-{idx}",
                proposal=proposal,
                autonomy_level=1
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(call_tool, i) for i in range(num_threads)]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                results.append(res)

        self.assertEqual(len(results), num_threads)
        for res in results:
            self.assertTrue(res.success, f"Concurrent execution failed: {res.error}")
            self.assertIsNone(res.error)
            self.assertIn("historical_email_count", res.output)

    def test_tenant_isolation_no_cross_tenant_leakage(self):
        """Proves interactions recorded in Tenant A are not leaked to Tenant B."""
        tenant_a = "tenant-alpha"
        tenant_b = "tenant-beta"
        sender = "vendor-partner@shared-vendor.com"
        recipient = "procurement@corp.internal"

        # Record interaction in Tenant A
        handle_record_interaction({
            "tenant_id": tenant_a,
            "sender_email": sender,
            "recipient_email": recipient,
            "auth_status": "PASS"
        })

        # Query from Tenant A -> Should find 1 record
        prop_a = ToolProposal(
            tool_name="query_sender_history",
            parameters={
                "sender_email": sender,
                "recipient_email": recipient,
                "tenant_id": tenant_a
            },
            reasoning="Tenant A query"
        )
        res_a = self.registry.execute_proposal(tenant_id=tenant_a, proposal=prop_a, autonomy_level=1)
        self.assertTrue(res_a.success)
        self.assertEqual(res_a.output.get("historical_email_count"), 1)
        self.assertFalse(res_a.output.get("is_first_time_sender"))

        # Query from Tenant B -> Should find 0 records (No leakage from Tenant A!)
        prop_b = ToolProposal(
            tool_name="query_sender_history",
            parameters={
                "sender_email": sender,
                "recipient_email": recipient,
                "tenant_id": tenant_b
            },
            reasoning="Tenant B query"
        )
        res_b = self.registry.execute_proposal(tenant_id=tenant_b, proposal=prop_b, autonomy_level=1)
        self.assertTrue(res_b.success)
        self.assertEqual(res_b.output.get("historical_email_count"), 0)
        self.assertTrue(res_b.output.get("is_first_time_sender"))

if __name__ == "__main__":
    unittest.main()
