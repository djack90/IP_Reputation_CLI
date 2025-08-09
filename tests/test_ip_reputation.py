import io
import unittest
from unittest.mock import patch
import ip_reputation

class ReputationTests(unittest.TestCase):
    @patch('ip_reputation.fetch_abuseipdb_score', return_value=80)
    @patch('ip_reputation.fetch_virustotal_score', return_value=5)
    def test_reputation_for_ips(self, mock_vt, mock_abuse):
        rows = ip_reputation.reputation_for_ips(['1.2.3.4'], 'a', 'b')
        self.assertEqual(rows, [{
            'ip': '1.2.3.4',
            'abuse_confidence_score': 80,
            'virustotal_reputation': 5,
        }])

    def test_write_csv(self):
        data = [{'ip': '1.2.3.4', 'abuse_confidence_score': 80, 'virustotal_reputation': 5}]
        buf = io.StringIO()
        ip_reputation.write_csv(data, buf)
        output = buf.getvalue().strip().splitlines()
        self.assertEqual(output[0], 'ip,abuse_confidence_score,virustotal_reputation')
        self.assertIn('1.2.3.4,80,5', output[1])

if __name__ == '__main__':
    unittest.main()
