"""Regression checks for graph pagination without a running localnet.

Run: python3 -m unittest discover -s localnet/e2e -p 'test_*.py'
"""
import http.server
import json
from pathlib import Path
import subprocess
import threading
import unittest
from urllib.parse import parse_qs, urlparse


class GraphQueriesTest(unittest.TestCase):
    def query(self, mode, function='graph_of_instance instance'):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                params = parse_qs(urlparse(self.path).query)
                offset, limit = int(params['offset'][0]), int(params['limit'][0])
                requests.append((offset, limit))
                self.send_response(400 if mode == 'http_error' or (mode == 'later_error' and offset) else 200)
                self.end_headers()
                rows = [{'graph': {'instance_id': 'instance', 'graph_id': str(i),
                                   'kickoff_index': i, 'status': 'L2Recorded'}}
                        for i in range(offset, min(offset + limit, 101))]
                body = {'graphs': rows, 'total': 101}
                if mode == 'http_error':
                    body = {'error': 'INVALID_LIMIT'}
                elif mode == 'empty':
                    body['graphs'] = []
                elif mode == 'invalid':
                    body = {'error': 'unexpected API error'}
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        source = Path(__file__).with_name('lib.sh').read_text()
        helpers = source[source.index('graphs_json() {'):source.index('pegbtc_sats()')]
        helpers += source[source.index('next_posted_graph() {'):source.index('# set_tuning')]
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            script = f'rpc_url() {{ echo http://127.0.0.1:{server.server_port}; }}\n'
            result = subprocess.run(['bash', '-c', script + helpers + '\n' + function],
                                    capture_output=True, text=True, timeout=15)
            server.shutdown()
            worker.join()
        return result, requests

    def test_all_pages_and_selection(self):
        result, requests = self.query('ok')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests, [(0, 100), (100, 100)])
        self.assertEqual(len(result.stdout.splitlines()), 101)
        self.assertIn('100 100 L2Recorded', result.stdout)
        result, _ = self.query('ok', 'graphs_on committee_0 instance')
        self.assertEqual(result.stdout.splitlines(), [str(i) for i in range(101)])
        result, _ = self.query('ok', 'next_posted_graph')
        self.assertEqual(result.stdout, '0\n')

    def test_query_errors_fail_without_results(self):
        for mode in ('http_error', 'later_error', 'empty', 'invalid'):
            with self.subTest(mode=mode):
                result, _ = self.query(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('graph query failed:', result.stderr)


if __name__ == '__main__':
    unittest.main()
